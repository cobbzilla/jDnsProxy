package com.moparisthebest.dns.listen.intercept;

import com.moparisthebest.dns.listen.TcpAsync;
import com.moparisthebest.dns.resolve.Resolver;

import java.net.*;
import java.util.concurrent.ExecutorService;

public class TcpAsyncIntercept extends TcpAsync {

    private InterceptionTarget target;

    public TcpAsyncIntercept(SocketAddress local, Resolver resolver, ExecutorService executor, InterceptionTarget target) {
        super(local, resolver, executor);
        this.target = target;
    }

    @Override
    protected byte[] intercept(byte[] buf, Object requestor) {
        if (target == null) return null;
        return target.intercept(buf, requestor);
    }

}
