#!/usr/bin/env python3
"""Find planted Log4j classpath resources in a project tree.

Log4j reads two files by fixed name from the classpath and applies them silently:

  log4j2.system.properties    every key is copied into the JVM system properties
  log4j2.component.properties Log4j's own configuration: the configuration file
                              location and the list of enabled script languages

A single file with either name on the classpath therefore reconfigures the JVM, and
Log4j's configuration can be pointed at a file the attacker ships in the same jar.

Usage:  ./scan_planted.py [path] [--json]
Exit:   0 = nothing found, 1 = at least one planted resource found.
"""

import argparse
import json
import os
import sys
import zipfile

PLANTED_FILES = ("log4j2.system.properties", "log4j2.component.properties")

SEVERITY = {
    "log4j2.system.properties": "CRITICAL",
    "log4j2.component.properties": "CRITICAL",
}

DETAIL = {
    "log4j2.system.properties": (
        "Log4j copies every key of this file into the JVM system properties at startup "
        "(log4j-api util/PropertiesUtil.java:506-519). That covers arbitrary JVM "
        "configuration - log4j.configurationFile, log4j2.Script.enableLanguages, proxy and "
        "TLS settings. Verified on log4j 2.14.1 - 2.26.1, and on log4j-api alone."
    ),
    "log4j2.component.properties": (
        "Log4j reads this file as its own property source. log4j.configurationFile in it "
        "points Log4j at another configuration file - which may be a classpath resource "
        "inside the same jar - and log4j2.Script.enableLanguages turns on script "
        "execution. Verified on log4j 2.14.1 - 2.26.1 (RCE)."
    ),
}

SKIP_DIRS = {".git", "node_modules", "target", ".venv", "__pycache__", ".m2", ".idea"}


def findings_in_jar(path):
    out = []
    try:
        with zipfile.ZipFile(path) as zf:
            for entry in zf.namelist():
                base = os.path.basename(entry)
                if base in PLANTED_FILES:
                    out.append((base, "%s!%s" % (path, entry)))
    except (OSError, zipfile.BadZipFile):
        pass
    return out


def scan(root):
    out = []
    if os.path.isfile(root):
        if root.endswith(".jar"):
            out.extend(findings_in_jar(root))
        elif os.path.basename(root) in PLANTED_FILES:
            out.append((os.path.basename(root), root))
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if name in PLANTED_FILES:
                out.append((name, path))
            elif name.endswith(".jar"):
                out.extend(findings_in_jar(path))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = [
        {"severity": SEVERITY.get(name, "CRITICAL"), "file": name, "location": loc, "detail": DETAIL.get(name, "")}
        for name, loc in scan(args.path)
    ]

    if args.json:
        print(json.dumps(rows, indent=2))
        return 1 if rows else 0

    if not rows:
        print("no planted log4j classpath resources under %s" % args.path)
        return 0
    for r in rows:
        print("%-8s %-28s %s" % (r["severity"], r["file"], r["location"]))
        print("         %s" % r["detail"])
    print("\n%d planted resource(s) found" % len(rows))
    return 1


if __name__ == "__main__":
    sys.exit(main())
