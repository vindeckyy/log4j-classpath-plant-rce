package lab;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Victim for the classpath pre-positioning chain.
 *
 * The attacker plants fixed-name resources somewhere on the application's classpath:
 *
 *   log4j2.system.properties    Log4j copies every key into the JVM system properties
 *   log4j2.component.properties Log4j configuration (log4j.configurationFile) + script languages
 *
 * The application never asks for this and never configures Log4j: Log4j does it during its own
 * initialization, before the first log statement is rendered.
 */
public final class ClasspathPoison {

    public static void main(final String[] args) {
        System.out.println("[1] planted system property BEFORE log4j init : " + System.getProperty("lab.planted"));
        final Logger log = LogManager.getLogger("victim");
        log.info("first log statement triggers log4j initialization");
        System.out.println("[2] planted system property AFTER  log4j init : " + System.getProperty("lab.planted"));
        System.out.println("[3] effective log4j config location             : " + System.getProperty("log4j.configurationFile"));
        System.out.println("[4] script languages enabled                     : " + System.getProperty("log4j2.Script.enableLanguages"));
        System.out.println("[5] attacker script executed (marker file)       : " + new java.io.File("/tmp/log4j-lab-pwned.txt").exists());
    }

    private ClasspathPoison() {}
}
