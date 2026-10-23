package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Victim that stays alive after Log4j initialization. The planted classpath resource turns
 * on the JMX remote agent with authentication disabled, so the attacker gets an
 * unauthenticated management channel to the whole JVM, not just to Log4j.
 */
public final class JmxVictim {

    public static void main(final String[] args) throws Exception {
        final Logger log = LogManager.getLogger("jmx-victim");
        log.info("victim started");
        System.out.println("[jmx-victim] jmx remote port property: " + System.getProperty("com.sun.management.jmxremote.port"));
        System.out.println("[jmx-victim] authenticate: " + System.getProperty("com.sun.management.jmxremote.authenticate"));
        // First use of the management API: the JMX agent reads its configuration here, i.e.
        // after Log4j has already rewritten the system properties from the planted file.
        System.out.println("[jmx-victim] management factory threads: " + java.lang.management.ManagementFactory.getPlatformMBeanServer().getMBeanCount());
        System.out.println("[jmx-victim] holding for 25s");
        System.out.flush();
        Thread.sleep(120_000L);
        System.out.println("[jmx-victim] done");
    }

    private JmxVictim() {}
}
