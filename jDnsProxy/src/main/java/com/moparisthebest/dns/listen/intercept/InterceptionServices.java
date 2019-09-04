package com.moparisthebest.dns.listen.intercept;

import com.moparisthebest.dns.listen.Listener;
import com.moparisthebest.dns.listen.Services;
import com.moparisthebest.dns.net.ParsedUrl;
import com.moparisthebest.dns.resolve.Resolver;

import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;

public class InterceptionServices implements Services {

    ServiceLoader<InterceptionTarget> services = ServiceLoader.load(InterceptionTarget.class);

    @Override
    public Listener getListener(ParsedUrl parsedUrl, final Resolver resolver, final ExecutorService executor) {
        final InterceptionTarget target = services.findFirst().orElse(null);
        switch(parsedUrl.getProtocol()) {
            case "tcp":
                return new TcpAsyncIntercept(parsedUrl.getAddr(), resolver, executor, target);
            case "udp":
                return new UdpSyncIntercept(parsedUrl.getAddr(), resolver, executor, target);
        }
        return null;
    }

}
