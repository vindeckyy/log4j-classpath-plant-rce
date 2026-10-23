package lab;

import org.apache.logging.log4j.LogManager;

/**
 * Blast radius check: this application has ONLY log4j-api on its classpath. It never
 * configures Log4j and never uses a Log4j appender. If the planted classpath resource
 * still rewrites the JVM's system properties, then the exposure is "every application that
 * merely has log4j-api on the classpath".
 */
public final class ApiOnly {

    public static void main(final String[] args) {
        System.out.println("[api-only] planted property BEFORE log4j init : " + System.getProperty("lab.planted"));
        LogManager.getLogger("api-only").info("hello");
        System.out.println("[api-only] planted property AFTER  log4j init : " + System.getProperty("lab.planted"));
        System.out.println("[api-only] log4j.configurationFile             : " + System.getProperty("log4j.configurationFile"));
    }

    private ApiOnly() {}
}
