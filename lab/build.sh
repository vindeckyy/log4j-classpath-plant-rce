#!/usr/bin/env bash
# Builds the lab. Java 8 bytecode so the victim can run on JDK 8 and 17.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/lib"
OUT="$ROOT/lab/build"
JAVAC="${JAVAC:-/usr/lib/jvm/java-8-openjdk-amd64/bin/javac}"
JAR="${JAR:-/usr/lib/jvm/java-8-openjdk-amd64/bin/jar}"

rm -rf "$OUT"
mkdir -p "$OUT/victim" "$OUT/attacker"

"$JAVAC" -d "$OUT/victim" -cp "$LIB/log4j-api-2.26.1.jar:$LIB/log4j-core-2.26.1.jar" \
    "$ROOT/lab/src/lab/ClasspathPoison.java" "$ROOT/lab/src/lab/ApiOnly.java" \
    "$ROOT/lab/src/lab/ProxyVictim.java" "$ROOT/lab/src/lab/JmxVictim.java" \
    "$ROOT/lab/src/lab/PolicyProbe.java"
"$JAVAC" -d "$OUT/attacker" "$ROOT/lab/src/lab/JmxProbe.java"

# the supply-chain case: one dependency jar that carries the planted classpath resource
"$JAR" cf "$OUT/evil-dependency.jar" -C "$ROOT/lab/poison-jar" .

echo "built -> $OUT"
