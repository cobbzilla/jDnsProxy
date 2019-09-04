package com.moparisthebest.dns.listen.intercept;

import org.minidns.dnsmessage.DnsMessage;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Properties;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RestApiInterceptionConfig {

    private static final String[] CONFIG_SEARCH_PATHS = { System.getProperty("user.dir"), "/etc"};
    private static final String REST_API_INTERCEPT_CONFIG = "jdnsproxy-interceptor.properties";

    // required fields
    public Inet4Address ip4;
    public Inet6Address ip6;
    public long dnsTtl;

    public String host;
    public String path;

    public int port;
    public String scheme = "http";
    public String nameParam = "name";
    public String ipParam = "ip";
    public long decisionTtl;
    public int maxConnections;

    public static RestApiInterceptionConfig load() {
        final Properties props = new Properties();
        for (String path : CONFIG_SEARCH_PATHS) {
            try (InputStream in = new FileInputStream(path + "/" + REST_API_INTERCEPT_CONFIG)) {
                props.load(in);
            } catch (Exception e) {}
        }
        if (props.isEmpty()) throw new RuntimeException(REST_API_INTERCEPT_CONFIG + " not found in paths: "+ Arrays.toString(CONFIG_SEARCH_PATHS));
        final RestApiInterceptionConfig config = new RestApiInterceptionConfig();

        try {
            config.ip4 = (Inet4Address) Inet4Address.getByName(props.getProperty("ip4"));
        } catch (Exception e) {
            throw new RuntimeException("load: ip4 was invalid: "+props.getProperty("ip4"));
        }
        try {
            config.ip6 = (Inet6Address) Inet6Address.getByName(props.getProperty("ip6"));
        } catch (Exception e) {
            throw new RuntimeException("load: ip6 was invalid: "+props.getProperty("ip6"));
        }

        config.scheme = props.getProperty("scheme", "http");
        config.host = props.getProperty("host");
        try {
            InetAddress.getByName(config.host);
        } catch (Exception e) {
            throw new RuntimeException("load: invalid host: "+config.host);
        }
        try {
            config.port = Integer.parseInt(props.getProperty("port", config.scheme.equals("http") ? "80" : "443"));
        } catch (Exception e) {
            throw new RuntimeException("load: invalid port: "+props.getProperty("port"));
        }
        config.path = props.getProperty("path", "/");
        if (!config.path.startsWith("/")) config.path = "/" + config.path;

        try {
            config.dnsTtl = Long.parseLong(props.getProperty("dnsTtl", "3600"));
        } catch (Exception e) {
            throw new RuntimeException("load: invalid dnsTtl: "+props.getProperty("dnsTtl"));
        }
        try {
            config.decisionTtl = Long.parseLong(props.getProperty("decisionTtl", "3600"));
        } catch (Exception e) {
            throw new RuntimeException("load: invalid decisionTtl: "+props.getProperty("decisionTtl"));
        }
        try {
            config.maxConnections = Integer.parseInt(props.getProperty("maxConnections", "100"));
        } catch (Exception e) {
            throw new RuntimeException("load: invalid maxConnections: "+props.getProperty("maxConnections"));
        }
        return config;
    }

    public String getUri(DnsMessage dnsMessage, Object requestor) {
        final String base = scheme + "://" + host + ":" + port + path;
        final String name = URLEncoder.encode(dnsMessage.getQuestion().name.toString(), UTF_8);
        final String req = getRequestorId(requestor);
        return base + "?"+nameParam+"=" + name + (req == null ? "" : "&"+ipParam+"=" + URLEncoder.encode(req, UTF_8));
    }

    protected String getRequestorId(Object requestor) {
        if (requestor instanceof InetAddress) {
            return ((InetAddress) requestor).getHostAddress();
        }
        return null;
    }
}
