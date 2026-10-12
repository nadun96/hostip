//! Reachability check end to end: a relay on localhost probes "this network"
//! (also localhost) the way it would probe a home's public IP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio_util::sync::CancellationToken;

use hostip::check::{self, CheckOptions, Listener, Observer, UdpReach};
use hostip::config::{Mode, PortRange, PortSpec};
use hostip::relay::{self, RelayOptions, TcpReach};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn free_tcp() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp() -> u16 {
    std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn tcp(public: u16, listen: u16) -> PortSpec {
    PortSpec::new(
        Mode::Auto,
        PortRange::single(3000),
        Some(PortRange::single(public)),
        Some(listen),
        None,
    )
    .unwrap()
}

fn udp(public: u16, local: u16) -> PortSpec {
    PortSpec::new(
        Mode::Udp,
        PortRange::single(local),
        Some(PortRange::single(public)),
        None,
        None,
    )
    .unwrap()
}

/// Starts a relay; returns its address and certificate fingerprint.
async fn start_relay(shutdown: &CancellationToken, dir: &std::path::Path) -> (String, String) {
    let control = free_tcp();
    let (tls, fingerprint) = relay::relay_tls(dir).unwrap();
    let opts = RelayOptions {
        listen: SocketAddr::new(LOCALHOST, control),
        token: "relay-secret".into(),
        public_ip: Some(LOCALHOST),
        allowed_ports: vec![PortRange {
            start: 1024,
            end: 65535,
        }],
    };
    tokio::spawn(relay::run_relay(opts, tls, shutdown.clone()));
    for _ in 0..50 {
        if tokio::net::TcpStream::connect((LOCALHOST, control))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    (format!("127.0.0.1:{control}"), fingerprint)
}

#[tokio::test]
async fn relay_probes_tcp_and_udp_ports() {
    let shutdown = CancellationToken::new();
    let dir = tempfile::tempdir().unwrap();
    let (address, fingerprint) = start_relay(&shutdown, dir.path()).await;

    // Reachable: the router would forward public == local here.
    let open_tcp = free_tcp();
    // Refused: "the router forwards" a public port where nothing listens.
    let (refused_public, refused_listen) = (free_tcp(), free_tcp());
    let open_udp = free_udp();
    // Not received: the datagram goes to the public port, the app is on another one.
    let (lost_public, lost_local) = (free_udp(), free_udp());
    // In use by the app: cannot be tested.
    let busy = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let busy_port = busy.local_addr().unwrap().port();

    let opts = CheckOptions {
        specs: vec![
            tcp(open_tcp, open_tcp),
            tcp(refused_public, refused_listen),
            udp(open_udp, open_udp),
            udp(lost_public, lost_local),
            udp(busy_port, busy_port),
        ],
        http_listen: None,
        observer: Some(Observer::new(&address, "relay-secret", &fingerprint).unwrap()),
        upnp: false,
        lan_ip: None,
    };
    let report = check::run(&opts).await;
    assert_eq!(report.observer_error, None);
    assert_eq!(report.observed_ip, Some(LOCALHOST));

    let tcp_of = |port| report.tcp.iter().find(|t| t.public == port).unwrap();
    assert_eq!(tcp_of(open_tcp).reach, Some(TcpReach::Open));
    assert_eq!(tcp_of(open_tcp).listener, Listener::Temporary);
    assert_eq!(tcp_of(refused_public).reach, Some(TcpReach::Refused));

    let udp_of = |port| report.udp.iter().find(|u| u.public == port).unwrap();
    assert_eq!(udp_of(open_udp).reach, Some(UdpReach::Received));
    assert_eq!(udp_of(lost_public).reach, Some(UdpReach::NotReceived));
    assert_eq!(udp_of(busy_port).reach, Some(UdpReach::NotTested));

    assert!(!report.all_reachable());
    let text = report.render();
    assert!(text.contains("REFUSED"), "{text}");
    assert!(text.contains("NOT RECEIVED"), "{text}");

    // The temporary listeners are gone afterwards.
    drop(busy);
    std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, open_tcp)).unwrap();
    shutdown.cancel();
}

#[tokio::test]
async fn everything_reachable_passes() {
    let shutdown = CancellationToken::new();
    let dir = tempfile::tempdir().unwrap();
    let (address, fingerprint) = start_relay(&shutdown, dir.path()).await;
    let (t, u) = (free_tcp(), free_udp());
    let opts = CheckOptions {
        specs: vec![tcp(t, t), udp(u, u)],
        http_listen: None,
        observer: Some(Observer::new(&address, "relay-secret", &fingerprint).unwrap()),
        upnp: false,
        lan_ip: None,
    };
    let report = check::run(&opts).await;
    assert!(report.all_reachable(), "{}", report.render());
    shutdown.cancel();
}

#[tokio::test]
async fn wrong_token_is_refused() {
    let shutdown = CancellationToken::new();
    let dir = tempfile::tempdir().unwrap();
    let (address, fingerprint) = start_relay(&shutdown, dir.path()).await;
    let t = free_tcp();
    let opts = CheckOptions {
        specs: vec![tcp(t, t)],
        http_listen: None,
        observer: Some(Observer::new(&address, "wrong", &fingerprint).unwrap()),
        upnp: false,
        lan_ip: None,
    };
    let report = check::run(&opts).await;
    assert!(
        report
            .observer_error
            .as_deref()
            .is_some_and(|e| e.contains("wrong token")),
        "{:?}",
        report.observer_error
    );
    assert!(!report.all_reachable());
    shutdown.cancel();
}
