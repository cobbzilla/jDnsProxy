package com.moparisthebest.dns.listen.intercept;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import static java.util.concurrent.TimeUnit.SECONDS;

public class RestApiInterceptionBulkLoader implements Runnable {

    public static final DateTimeFormatter DATE_FORMAT_IF_MOD_SINCE = DateTimeFormat.forPattern("EEE, dd MMM yyyy HH:mm:ss zzz");

    public long sleepInterval;
    public BulkLoadMode mode;
    public RestApiInterceptionConfig config;
    public RestApiInterceptionCache cache;

    private final PoolingHttpClientConnectionManager cm;

    public RestApiInterceptionBulkLoader(RestApiInterceptionConfig config, long interval, BulkLoadMode mode, RestApiInterceptionCache cache) {
        this.config = config;
        this.sleepInterval = interval;
        this.mode = mode;
        this.cache = cache;

        cm = new PoolingHttpClientConnectionManager();
        cm.setMaxTotal(10);
        cm.setMaxPerRoute(new HttpRoute(new HttpHost(config.host)), 10);

        final Thread t = new Thread(this);
        t.setDaemon(true);
        t.start();
    }

    @Override public void run() {
        boolean first = true;
        while (true) {
            final String prefix = logPrefix();
            try {
                if (first && mode == BulkLoadMode.add) {
                    // a replace-mode loader is also running. first time through, skip our run and avoid hitting the API
                    // twice quickly. so we sleep a little extra here
                    System.err.println(prefix + "sleeping for " + sleepInterval + " seconds");
                    Thread.sleep(SECONDS.toMillis(sleepInterval));
                    first = false;
                }
                System.err.println(prefix + "starting refresh...");
                refresh();

            } catch (Exception e) {
                System.err.println(prefix + "error refreshing: " +e);
                e.printStackTrace();
            }
            try {
                System.err.println(prefix + "sleeping for " + sleepInterval + " seconds");
                Thread.sleep(SECONDS.toMillis(sleepInterval));
            } catch (InterruptedException e) {
                System.err.println(prefix + "interrupted!");
                return;
            }
        }

    }

    private String logPrefix() {
        return "BackgroundLoader("+mode.name()+"): ";
    }

    private void refresh() {
        final String prefix = logPrefix();
        try (CloseableHttpClient client = HttpClients.custom()
                .setConnectionManager(cm)
                .setConnectionManagerShared(true)
                .build()) {

            // build the URI
            final String uri = config.getUri(null, null);

            final HttpUriRequest apiRequest = mode.getRequest(uri, cache.getLastMod());
            System.err.println(prefix + "exec'ing request: "+apiRequest.toString());
            try (CloseableHttpResponse response = client.execute(apiRequest)) {
                final int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode / 100 != 2) throw new IllegalStateException("refresh: unexpected status: "+statusCode);
                final HttpEntity entity = response.getEntity();
                if (entity == null) throw new IllegalStateException("refresh: missing entity body");
                final List<String> intercepts = new ArrayList<>(); // todo: size this based on Content-Length
                try (BufferedReader r = new BufferedReader(new InputStreamReader(entity.getContent()))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        intercepts.add(line);
                    }
                }
                System.err.println(prefix + "refresh found intercepts: "+intercepts);
                if (intercepts.isEmpty()) return;
                cache.update(intercepts, mode);
            }

        } catch (Exception e) {
            System.err.println("refresh: "+e);
            e.printStackTrace();
        }
    }
}
