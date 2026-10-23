#!/usr/bin/env bash
# Fetches everything the lab needs. Nothing large is stored in git.
#
#   ./setup.sh    jars + the Log4j sources cited in WORKUP.md
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M=https://repo1.maven.org/maven2

# The versions the exploitability matrix in WORKUP.md covers.
LOG4J_VERSIONS="2.14.1 2.17.1 2.24.0 2.25.1 2.26.1"

mkdir -p "$ROOT/lib" "$ROOT/sources"

echo "== log4j jars"
for v in $LOG4J_VERSIONS; do
    for a in log4j-api log4j-core; do
        f="$a-$v.jar"
        [ -f "$ROOT/lib/$f" ] || curl -sS -m 120 -o "$ROOT/lib/$f" "$M/org/apache/logging/log4j/$a/$v/$f"
    done
done

echo "== lab dependencies"
curl -sS -m 180 -o "$ROOT/lib/groovy-4.0.24.jar" "$M/org/apache/groovy/groovy/4.0.24/groovy-4.0.24.jar"
curl -sS -m 120 -o "$ROOT/lib/groovy-jsr223-4.0.24.jar" \
    "$M/org/apache/groovy/groovy-jsr223/4.0.24/groovy-jsr223-4.0.24.jar"

echo "== Log4j sources (for the file:line citations)"
curl -sS -m 120 -o "$ROOT/sources/log4j-api-2.26.1-sources.jar" \
    "$M/org/apache/logging/log4j/log4j-api/2.26.1/log4j-api-2.26.1-sources.jar"
mkdir -p "$ROOT/sources/api-2.26.1"
(cd "$ROOT/sources/api-2.26.1" && unzip -oq "../log4j-api-2.26.1-sources.jar")

curl -sS -m 120 -o "$ROOT/sources/log4j-core-2.26.1-sources.jar" \
    "$M/org/apache/logging/log4j/log4j-core/2.26.1/log4j-core-2.26.1-sources.jar"
mkdir -p "$ROOT/sources/core-2.26.1"
(cd "$ROOT/sources/core-2.26.1" && unzip -oq "../log4j-core-2.26.1-sources.jar")

# Log4j 3.x: the beta3 core needs an api that is not published (log4j-api stops at
# 3.0.0-beta2), so the 3.x statements in WORKUP.md rest on the 3.0.0-beta2 API source.
curl -sS -m 120 -o "$ROOT/lib/log4j-api-3.0.0-beta2.jar" \
    "$M/org/apache/logging/log4j/log4j-api/3.0.0-beta2/log4j-api-3.0.0-beta2.jar"
curl -sS -m 120 -o "$ROOT/sources/log4j-api-3.0.0-beta2-sources.jar" \
    "$M/org/apache/logging/log4j/log4j-api/3.0.0-beta2/log4j-api-3.0.0-beta2-sources.jar"
mkdir -p "$ROOT/sources/api-3.0.0-beta2"
(cd "$ROOT/sources/api-3.0.0-beta2" && unzip -oq "../log4j-api-3.0.0-beta2-sources.jar")

echo "done. now: ./lab/build.sh && ./lab/verify.sh"
