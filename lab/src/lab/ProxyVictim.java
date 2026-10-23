package lab;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Second impact of the classpath plant: the planted file rewrites JVM-wide system
 * properties, so it can also redirect the application's outbound traffic. The victim's
 * HTTP request ends up at the attacker's proxy, which is where the credentials go.
 */
public final class ProxyVictim {

    public static void main(final String[] args) {
        final Logger log = LogManager.getLogger("proxy-victim");
        log.info("victim started");
        System.out.println("[proxy-victim] http.proxyHost = " + System.getProperty("http.proxyHost"));
        System.out.println("[proxy-victim] http.proxyPort = " + System.getProperty("http.proxyPort"));
        try {
            final URL url = new URL("http://vault.internal/api/login?user=alice&token=s3cr3t");
            final HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            try (InputStream in = conn.getInputStream()) {
                System.out.println("[proxy-victim] response status = " + conn.getResponseCode());
            }
        } catch (final Exception e) {
            System.out.println("[proxy-victim] request failed: " + e);
        }
    }

    private ProxyVictim() {}
}
