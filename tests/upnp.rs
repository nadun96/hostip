//! Port mapping against a fake UPnP-IGD router speaking real SSDP + SOAP.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;

use hostip::portmap::{self, DiscoverOptions, Mapping, PortMapper, Proto};

const SERVICE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// (action, external port, protocol, internal client, internal port, lease)
type Call = (String, String, String, String, String, String);

#[derive(Default)]
struct Router {
    calls: Mutex<Vec<Call>>,
    permanent_only: bool,
    in_use: Option<u16>,
}

fn tag(body: &str, name: &str) -> String {
    let open = format!("<{name}>");
    body.split_once(&open)
        .and_then(|(_, rest)| rest.split_once(&format!("</{name}>")))
        .map(|(value, _)| value.to_owned())
        .unwrap_or_default()
}

fn envelope(inner: &str) -> String {
    format!(
        r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>{inner}</s:Body></s:Envelope>"#
    )
}

fn fault(code: u16) -> Response<Full<Bytes>> {
    let body = envelope(&format!(
        r#"<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>{code}</errorCode><errorDescription>error</errorDescription></UPnPError></detail></s:Fault>"#
    ));
    let mut resp = Response::new(Full::from(body));
    *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

const ROOT_DESC: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <deviceList><device>
      <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
      <deviceList><device>
        <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
        <serviceList><service>
          <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
          <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
          <controlURL>/ctl/IPConn</controlURL>
          <eventSubURL>/evt/IPConn</eventSubURL>
          <SCPDURL>/WANIPCn.xml</SCPDURL>
        </service></serviceList>
      </device></deviceList>
    </device></deviceList>
  </device>
</root>"#;

fn scpd() -> String {
    let arg = |name: &str, dir: &str| {
        format!("<argument><name>{name}</name><direction>{dir}</direction></argument>")
    };
    let action = |name: &str, args: &[(&str, &str)]| {
        let args: String = args.iter().map(|(n, d)| arg(n, d)).collect();
        format!("<action><name>{name}</name><argumentList>{args}</argumentList></action>")
    };
    let add = action(
        "AddPortMapping",
        &[
            ("NewRemoteHost", "in"),
            ("NewExternalPort", "in"),
            ("NewProtocol", "in"),
            ("NewInternalPort", "in"),
            ("NewInternalClient", "in"),
            ("NewEnabled", "in"),
            ("NewPortMappingDescription", "in"),
            ("NewLeaseDuration", "in"),
        ],
    );
    let delete = action(
        "DeletePortMapping",
        &[
            ("NewRemoteHost", "in"),
            ("NewExternalPort", "in"),
            ("NewProtocol", "in"),
        ],
    );
    let ip = action("GetExternalIPAddress", &[("NewExternalIPAddress", "out")]);
    format!(
        r#"<?xml version="1.0"?><scpd xmlns="urn:schemas-upnp-org:service-1-0"><actionList>{add}{delete}{ip}</actionList></scpd>"#
    )
}

async fn handle(
    req: Request<Incoming>,
    router: Arc<Router>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let ok = |body: String| Ok(Response::new(Full::from(body)));
    match req.uri().path() {
        "/rootDesc.xml" => ok(ROOT_DESC.to_owned()),
        "/WANIPCn.xml" => ok(scpd()),
        "/ctl/IPConn" => {
            let action = req
                .headers()
                .get("soapaction")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim_matches('"').split('#').nth(1))
                .unwrap_or_default()
                .to_owned();
            let body =
                String::from_utf8(req.into_body().collect().await.unwrap().to_bytes().to_vec())
                    .unwrap();
            let external = tag(&body, "NewExternalPort");
            let lease = tag(&body, "NewLeaseDuration");
            if action == "AddPortMapping" {
                if router.permanent_only && lease != "0" {
                    return Ok(fault(725));
                }
                if router.in_use.is_some_and(|p| p.to_string() == external) {
                    return Ok(fault(718));
                }
            }
            router.calls.lock().unwrap().push((
                action.clone(),
                external,
                tag(&body, "NewProtocol"),
                tag(&body, "NewInternalClient"),
                tag(&body, "NewInternalPort"),
                lease,
            ));
            let inner = match action.as_str() {
                "GetExternalIPAddress" => format!(
                    r#"<u:GetExternalIPAddressResponse xmlns:u="{SERVICE}"><NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse>"#
                ),
                other => format!(r#"<u:{other}Response xmlns:u="{SERVICE}"></u:{other}Response>"#),
            };
            ok(envelope(&inner))
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::default())
            .unwrap()),
    }
}

/// Starts the fake router; returns the SSDP address to search.
async fn start_router(router: Arc<Router>) -> SocketAddr {
    let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    let state = router.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = http.accept().await.unwrap();
            let state = state.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req| handle(req, state.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let ssdp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let ssdp_addr = ssdp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (_, from) = ssdp.recv_from(&mut buf).await.unwrap();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                 USN: uuid:fake::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\n\
                 LOCATION: http://127.0.0.1:{http_port}/rootDesc.xml\r\n\r\n"
            );
            let _ = ssdp.send_to(reply.as_bytes(), from).await;
        }
    });
    ssdp_addr
}

fn options(ssdp: SocketAddr) -> DiscoverOptions {
    DiscoverOptions {
        ssdp_target: Some(ssdp),
        search_timeout: Duration::from_secs(3),
        try_pcp: false,
        allowed_gateway_ips: vec![Ipv4Addr::LOCALHOST.into()],
    }
}

const LAN: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

fn tcp(external: u16, internal: u16) -> Mapping {
    Mapping {
        proto: Proto::Tcp,
        external,
        internal,
    }
}

#[tokio::test]
async fn maps_and_removes_ports_via_upnp() {
    let router = Arc::new(Router::default());
    let ssdp = start_router(router.clone()).await;

    let mut mapper = PortMapper::discover(LAN, &options(ssdp)).await.unwrap();
    assert_eq!(mapper.method(), "UPnP");
    assert_eq!(
        mapper.external_ip().await,
        Some("203.0.113.7".parse().unwrap())
    );

    let udp = Mapping {
        proto: Proto::Udp,
        external: 3478,
        internal: 3478,
    };
    let report = mapper
        .map_all(&[tcp(443, 443), tcp(3000, 13000), udp])
        .await;
    assert_eq!(report.mapped.len(), 3);
    assert!(report.failed.is_empty());
    mapper.remove_all().await;

    let calls = router.calls.lock().unwrap().clone();
    let adds: Vec<_> = calls
        .iter()
        .filter(|c| c.0 == "AddPortMapping")
        .map(|c| {
            (
                c.1.as_str(),
                c.2.as_str(),
                c.3.as_str(),
                c.4.as_str(),
                c.5.as_str(),
            )
        })
        .collect();
    assert_eq!(
        adds,
        [
            ("443", "TCP", "192.168.1.10", "443", "3600"),
            ("3000", "TCP", "192.168.1.10", "13000", "3600"),
            ("3478", "UDP", "192.168.1.10", "3478", "3600"),
        ]
    );
    let deletes = calls.iter().filter(|c| c.0 == "DeletePortMapping").count();
    assert_eq!(deletes, 3);
}

#[tokio::test]
async fn falls_back_to_permanent_leases() {
    let router = Arc::new(Router {
        permanent_only: true,
        ..Router::default()
    });
    let ssdp = start_router(router.clone()).await;
    let mut mapper = PortMapper::discover(LAN, &options(ssdp)).await.unwrap();
    let report = mapper.map_all(&[tcp(443, 443), tcp(80, 80)]).await;
    assert_eq!(report.mapped.len(), 2, "{:?}", report.failed);
    let leases: Vec<_> = router
        .calls
        .lock()
        .unwrap()
        .iter()
        .map(|c| c.5.clone())
        .collect();
    assert_eq!(leases, ["0", "0"]);
}

#[tokio::test]
async fn reports_ports_taken_by_other_devices() {
    let router = Arc::new(Router {
        in_use: Some(80),
        ..Router::default()
    });
    let ssdp = start_router(router).await;
    let mut mapper = PortMapper::discover(LAN, &options(ssdp)).await.unwrap();
    let report = mapper.map_all(&[tcp(443, 443), tcp(80, 80)]).await;
    assert_eq!(report.mapped, [tcp(443, 443)]);
    assert_eq!(report.failed.len(), 1);
    assert!(
        report.failed[0].1.contains("another device"),
        "{}",
        report.failed[0].1
    );
}

#[tokio::test]
async fn run_maps_then_cleans_up_on_shutdown() {
    let router = Arc::new(Router::default());
    let ssdp = start_router(router.clone()).await;
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(portmap::run(
        LAN,
        vec![tcp(443, 443)],
        options(ssdp),
        shutdown.clone(),
    ));
    for _ in 0..50 {
        if !router.calls.lock().unwrap().is_empty()
            && router
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.0 == "AddPortMapping")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    shutdown.cancel();
    task.await.unwrap();
    let calls = router.calls.lock().unwrap().clone();
    assert!(calls.iter().any(|c| c.0 == "AddPortMapping"));
    assert!(calls.iter().any(|c| c.0 == "DeletePortMapping"));
}

#[tokio::test]
async fn reports_missing_router() {
    // Nothing answers SSDP here.
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let mut opts = options(silent.local_addr().unwrap());
    opts.search_timeout = Duration::from_millis(300);
    let err = PortMapper::discover(LAN, &opts).await.err().unwrap();
    assert!(err.to_string().contains("no UPnP router found"), "{err}");
}
