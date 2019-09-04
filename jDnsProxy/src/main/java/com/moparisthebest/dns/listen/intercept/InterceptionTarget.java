package com.moparisthebest.dns.listen.intercept;

import org.minidns.dnsmessage.DnsMessage;
import org.minidns.dnsmessage.Question;
import org.minidns.record.*;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;

public interface InterceptionTarget {

    Inet4Address getIp4();
    Inet6Address getIp6();
    default long getDecisionTtl () { return 3600; }
    default long getDnsTtl() { return 3600; }

    default boolean canIntercept(DnsMessage dnsMessage, Object requestor) throws IOException {
        switch (dnsMessage.getQuestion().type) {
            case A: case AAAA: case CNAME: return true;
            default: return false;
        }
    }

    default boolean shouldIntercept(DnsMessage buf, Object requestor) { return false; }

    default byte[] intercept(byte[] buf, Object requestor) {
        try {
            final DnsMessage dnsMessage = new DnsMessage(buf);
            if (canIntercept(dnsMessage, requestor) && shouldIntercept(dnsMessage, requestor)) {
                final byte[] interception = buildInterception(buf, dnsMessage, requestor);
                if (interception != null) return interception;
            }
        } catch (Exception e) {
            // todo: log this
            System.err.println(getClass().getSimpleName()+".intercept: "+e);
            e.printStackTrace();
        }
        return null;
    }

    default byte[] buildInterception(byte[] buf, DnsMessage request, Object requestor) {
        if (shouldIntercept(request, requestor)) {
            try {
                final InternetAddressRR rr;
                final Question question = request.getQuestion();
                switch (question.type) {
                    case A: rr = new A(getIp4()); break;
                    case AAAA: if (getIp6() == null) return null; rr = new AAAA(getIp6()); break;
                    case CNAME: rr = new A(getIp4()); break;
                    default: return null;
                }
                final DnsMessage response = DnsMessage.builder()
                        .setId(request.id)
                        .addQuestion(question)
                        .addAnswer(new Record<Data>(question.name, question.type, question.clazz.getValue(), getDnsTtl(), rr))
                        .setAuthoritativeAnswer(true)
                        .build();
                return response.toArray();

            } catch (Exception e) {
                System.err.println(getClass().getSimpleName()+".intercept (buf.length was "+buf.length+"): "+e);
                e.printStackTrace();
            }
        }
        return null;
    }
}
