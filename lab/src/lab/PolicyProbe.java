package lab;

import org.apache.logging.log4j.LogManager;

/**
 * Shows that the planted classpath resource can carry a *lookup expression* into the
 * configuration-time evaluation, where Log4j's recursive substitutor is active.
 *
 * The runtime substitutor deliberately refuses to evaluate lookups inside a lookup's result —
 * that is the guardrail that contains untrusted context data. A value planted as a JVM system
 * property is read by the configuration substitutor, which does evaluate nested lookups, so
 * the guardrail does not extend to this input channel.
 *
 * The planted file sets `lab.leak=${env:HOME}`; the configuration's pattern interpolates
 * `${sys:lab.leak}`. If the value is evaluated recursively, the log line shows the expanded
 * environment variable; if it is not, it shows the literal expression.
 */
public final class PolicyProbe {

    public static void main(final String[] args) {
        System.out.println("[before log4j init] lab.leak = " + System.getProperty("lab.leak"));
        LogManager.getLogger("policy-probe").info("hello");
        System.out.println("[after  log4j init] lab.leak = " + System.getProperty("lab.leak"));
    }

    private PolicyProbe() {}
}
