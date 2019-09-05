package com.moparisthebest.dns.listen.intercept;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;

import java.util.function.Function;

import static com.moparisthebest.dns.listen.intercept.RestApiInterceptionBulkLoader.DATE_FORMAT_IF_MOD_SINCE;

public enum BulkLoadMode {

    add (HttpPost.class, (b) -> {
        if (b.lastMod != null) {
            System.err.println("add: adding If-Modified-Since: "+DATE_FORMAT_IF_MOD_SINCE.print(b.lastMod));
            b.request.addHeader("If-Modified-Since", DATE_FORMAT_IF_MOD_SINCE.print(b.lastMod));
        }
        return b;
    }),

    replace (HttpPut.class, (r) -> r);

    private Class<? extends HttpUriRequest> requestClass;
    private Function<BulkLoad, BulkLoad> headerFunc;

    BulkLoadMode (Class<? extends HttpUriRequest> requestClass, Function<BulkLoad, BulkLoad> headerFunc) {
        this.requestClass = requestClass;
        this.headerFunc = headerFunc;
    }

    // we only need one of these ever, it's used to find the constructor. make it a constant
    public static final Class<?>[] C_ARGS = {String.class};

    public HttpUriRequest getRequest(String uri, Long lastMod) {
        try {
            final HttpUriRequest request = requestClass.getDeclaredConstructor(C_ARGS).newInstance(uri);
            return headerFunc.apply(new BulkLoad(request, lastMod)).request;
        } catch (Exception e) {
            throw new IllegalStateException("getRequest: "+e, e);
        }
    }

    private class BulkLoad {
        public HttpUriRequest request;
        public Long lastMod;
        public BulkLoad(HttpUriRequest request, Long lastMod) {
            this.request = request;
            this.lastMod = lastMod;
        }
    }
}
