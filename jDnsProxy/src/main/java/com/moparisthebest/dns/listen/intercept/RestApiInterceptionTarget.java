package com.moparisthebest.dns.listen.intercept;

import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.minidns.dnsmessage.DnsMessage;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static java.lang.System.currentTimeMillis;

public class RestApiInterceptionTarget implements InterceptionTarget, RestApiInterceptionCache {

    private RestApiInterceptionConfig config;
    private final PoolingHttpClientConnectionManager cm;

    public RestApiInterceptionTarget() {
        config = RestApiInterceptionConfig.load();
        cm = new PoolingHttpClientConnectionManager();
        cm.setMaxTotal(config.maxConnections);
        cm.setMaxPerRoute(new HttpRoute(new HttpHost(config.host)), config.maxConnections);

        if (config.mode.isBulk()) {
            new RestApiInterceptionBulkLoader(config, config.backgroundLoadInterval, BulkLoadMode.add, this);
            new RestApiInterceptionBulkLoader(config, config.fullBackgroundLoadInterval, BulkLoadMode.replace, this);
        }
    }

    private volatile Long lastMod = null;
    @Override public Long getLastMod() { return lastMod; }

    @Override public void update(List<String> intercepts, BulkLoadMode mode) {
        switch (mode) {
            case add:
                for (String i : intercepts) bulkLoad.put(i, i);
                break;

            case replace:
                final Map<String, String> b = new ConcurrentHashMap<>();
                for (String i : intercepts) b.put(i, i);
                bulkLoad = b;
                break;

            default:
                throw new IllegalArgumentException("update: invalid mode: "+mode);
        }
        lastMod = currentTimeMillis();
    }

    @Override public Inet4Address getIp4() { return config.ip4; }
    @Override public Inet6Address getIp6() { return config.ip6; }
    @Override public long getDecisionTtl() { return config.decisionTtl; }
    @Override public long getDnsTtl() { return config.dnsTtl; }

    private volatile Map<String, String> bulkLoad = new ConcurrentHashMap<>();
    private Map<String, ApiCacheEntry> cache = new ConcurrentHashMap<>();

    private String cacheKey (DnsMessage dnsMessage, Object requestor) {
        return dnsMessage.hashCode() + ":" + (requestor == null ? "null" : requestor.hashCode());
    }

    private ApiCacheEntry cachedDecision(String key) {
        final ApiCacheEntry entry = cache.get(key);
        if (entry != null && entry.expired()) {
            System.err.println("cachedDecision: entry expired, removing and returning null");
            cache.remove(key);
            return null;
        }
        return entry;
    }

    @Override public boolean shouldIntercept(DnsMessage dnsMessage, Object requestor) {

        if (config.mode.isBulk()) {
            return bulkLoad.containsKey(dnsMessage.getQuestion().name.toString());
        }

        final String key = cacheKey(dnsMessage, requestor);
        ApiCacheEntry entry = cachedDecision(key);
        if (entry != null) return entry.decision;

        try (CloseableHttpClient client = HttpClients.custom()
                .setConnectionManager(cm)
                .setConnectionManagerShared(true)
                .build()) {

            // build the URI
            final String uri = config.getUri(dnsMessage, requestor);

            final HttpGet apiRequest = new HttpGet(uri);
            try (CloseableHttpResponse response = client.execute(apiRequest)) {
                final int statusCode = response.getStatusLine().getStatusCode();

                entry = new ApiCacheEntry(statusCode / 100 == 2);
                cache.put(key, entry);
                if (entry.decision) {
                    return true;
                } else {
                    System.out.println("shouldIntercept: API returned false (status "+statusCode+")");
                    return false;
                }
            }

        } catch (Exception e) {
            System.err.println("shouldIntercept: "+e);
            e.printStackTrace();
        }
        return false;
    }

    private class ApiCacheEntry {
        final boolean decision;
        final long ctime = currentTimeMillis();

        public ApiCacheEntry(boolean decision) { this.decision = decision; }

        public boolean expired() { return currentTimeMillis() - ctime > TimeUnit.SECONDS.toMillis(config.decisionTtl); }
    }
}
