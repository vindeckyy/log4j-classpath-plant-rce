# Security Policy

## What this repository is

This is a **security disclosure** for Apache Log4j (`log4j-api` and `log4j-core`): Log4j reads
two fixed-name resources from the classpath and applies them silently — one of them becomes
**JVM system properties**, the other becomes **Log4j's configuration** — which yields remote
code execution. See `README.md` for the finding and `WORKUP.md` for the full analysis.

**Disclosure status:** the behaviour of `log4j2.system.properties` is documented by the Log4j
project (a convenience feature); the security consequence — that a classpath resource silently
reconfigures the JVM and hijacks Log4j's configuration — is not addressed anywhere in that
documentation or in any advisory.

This finding was derived in the same audit as the configuration-time evaluation finding in the
sibling repository `log4j-vuln-lab`, where it was first written up in that repository's
history (commit `e31dbee`) before it was moved here for a separate disclosure. It has not been
reported to the Apache Logging Services project or any other vendor, and it has not been
published anywhere else.

## If you are affected

Please forward the finding to the vendor so it can be addressed in a supported release:

* Apache Logging Services security team: <security@apache.org>
* Process and reporting guidelines: <https://logging.apache.org/security.html>

## If you find a problem *in this repository*

Open an issue on this repository. Do **not** report it to the Apache Logging Services
team — it is a bug in the lab, not in Log4j.

## Using the lab

Everything in `lab/` binds to `127.0.0.1` and targets only the victim process it starts itself.
Do not point the lab at systems you do not own or are not authorised to test.
