#!/usr/bin/env bash
# Walks through the branch flow of docs/WORKFLOW.md in a throwaway local repository:
#
#   feature/* --merge--> dev --tests pass--> test --tests pass--> main
#
# A toy app ("add" two numbers) is tested against test data in cases.csv. One
# feature is good and reaches main; one is broken and is stopped at dev. The
# promotions use the same scripts/promote.sh as the real pipeline.
#
#   scripts/demo-flow.sh            # nothing outside a temporary folder is touched
set -euo pipefail

promote="$(cd "$(dirname "$0")" && pwd)/promote.sh"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
export GIT_AUTHOR_NAME=demo GIT_AUTHOR_EMAIL=demo@example.com
export GIT_COMMITTER_NAME=demo GIT_COMMITTER_EMAIL=demo@example.com
# Local pushes don't need negotiation; some global configs turn it on noisily.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=push.negotiate GIT_CONFIG_VALUE_0=false

git init --quiet --bare --initial-branch=main "$root/origin.git"
git clone --quiet "$root/origin.git" "$root/work" 2>/dev/null
cd "$root/work"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
heads() {
    for b in main test dev; do
        printf '   %-5s %s\n' "$b" "$(git log -1 --format='%h %s' "origin/$b")"
    done
}

# The test runner: every row of cases.csv is `operation,a,b,expected`.
run_tests() {
    local failed=0 op a b want got
    while IFS=, read -r op a b want; do
        [ "$op" = op ] && continue
        got="$(./app.sh "$op" "$a" "$b")"
        if [ "$got" = "$want" ]; then
            echo "   pass  $op $a $b = $want"
        else
            echo "   FAIL  $op $a $b: expected $want, got $got"
            failed=1
        fi
    done <cases.csv
    return $failed
}

# Stage = run the tests on a branch's tip, then fast-forward the next branch to it.
stage() {
    local from="$1" to="$2"
    git checkout --quiet "origin/$from"
    echo "-- tests on $from ($(git rev-parse --short HEAD))"
    if run_tests; then
        "$promote" HEAD "$to" | sed 's/^/   /'
        git fetch --quiet origin
        return 0
    else
        echo "   tests failed: $to stays where it was"
        return 1
    fi
}

say "Start: main, test and dev at the same commit"
cat >app.sh <<'APP'
#!/usr/bin/env bash
case "$1" in
  add) echo $(($2 + $3)) ;;
esac
APP
chmod +x app.sh
cat >cases.csv <<'CSV'
op,a,b,expected
add,2,3,5
add,-4,4,0
CSV
git add . && git commit --quiet -m "app: add"
git push --quiet origin main
git push --quiet origin main:dev main:test
git fetch --quiet origin
heads

say "Feature 1 (good): feature/multiply adds an operation and its test data"
git checkout --quiet -b feature/multiply origin/dev
sed -i.bak 's/^esac$/  mul) echo $(($2 * $3)) ;;\nesac/' app.sh && rm app.sh.bak
printf 'mul,6,7,42\nmul,-3,5,-15\n' >>cases.csv
git commit --quiet -am "app: multiply"
git push --quiet origin feature/multiply
echo "-- pull request feature/multiply -> dev is reviewed and merged"
git checkout --quiet -B dev origin/dev
git merge --quiet --no-ff -m "Merge feature/multiply" feature/multiply
git push --quiet origin dev
git fetch --quiet origin
heads
stage dev test
stage test main
heads

say "Feature 2 (broken): feature/subtract has a bug the test data catches"
git checkout --quiet -b feature/subtract origin/dev
sed -i.bak 's/^esac$/  sub) echo $(($2 + $3)) ;;\nesac/' app.sh && rm app.sh.bak
printf 'sub,10,4,6\n' >>cases.csv
git commit --quiet -am "app: subtract (buggy)"
echo "-- merged into dev"
git checkout --quiet -B dev origin/dev
git merge --quiet --no-ff -m "Merge feature/subtract" feature/subtract
git push --quiet origin dev
git fetch --quiet origin
stage dev test || true
heads
echo "   main still has only tested code."

say "Fix: a new commit on dev, and the flow continues"
git checkout --quiet -B dev origin/dev
sed -i.bak 's/sub) echo $(($2 + $3))/sub) echo $(($2 - $3))/' app.sh && rm app.sh.bak
git commit --quiet -am "app: fix subtract"
git push --quiet origin dev
git fetch --quiet origin
stage dev test
stage test main
heads

say "Promoted by hand: a dev -> test pull request merged on GitHub adds a merge commit"
git checkout --quiet -B dev origin/dev
printf 'add,100,1,101\n' >>cases.csv
git commit --quiet -am "more test data"
git push --quiet origin dev
git checkout --quiet -B test origin/test
git merge --quiet --no-ff -m "Merge pull request: dev -> test" origin/dev
git push --quiet origin test
git fetch --quiet origin
heads
stage test main
echo "-- the next feature: test now has a merge commit that dev lacks, but it adds nothing"
git checkout --quiet -B dev origin/dev
printf 'mul,0,9,0\n' >>cases.csv
git commit --quiet -am "even more test data"
git push --quiet origin dev
git fetch --quiet origin
stage dev test
stage test main
heads

say "Guard: a commit made directly on main is never overwritten"
git checkout --quiet -B main origin/main
echo "# hotfix" >>app.sh
git commit --quiet -am "hotfix straight on main"
git push --quiet origin main
git checkout --quiet -B dev origin/dev
echo "# next feature" >>cases.csv
git commit --quiet -am "next feature"
git push --quiet origin dev
git fetch --quiet origin
git checkout --quiet origin/dev
"$promote" HEAD test | sed 's/^/   /'
"$promote" HEAD main 2>&1 | sed 's/^/   /' || echo "   refused: merge main into dev, then the flow continues"
