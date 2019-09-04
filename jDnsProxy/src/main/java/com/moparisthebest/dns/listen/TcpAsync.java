package com.moparisthebest.dns.listen;

import com.moparisthebest.dns.dto.Packet;
import com.moparisthebest.dns.net.BufChan;
import com.moparisthebest.dns.net.FullReadCompletionHandler;
import com.moparisthebest.dns.net.FullWriteCompletionHandler;
import com.moparisthebest.dns.net.FunctionalCompletionHandler;
import com.moparisthebest.dns.resolve.Resolver;

import java.io.IOException;
import java.net.SocketAddress;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.ExecutorService;

public class TcpAsync implements Listener {
    private final FunctionalCompletionHandler<AsynchronousSocketChannel, AsynchronousServerSocketChannel> newConnection = new FunctionalCompletionHandler<AsynchronousSocketChannel, AsynchronousServerSocketChannel>() {
        @Override
        public void completed(final AsynchronousSocketChannel sock, final AsynchronousServerSocketChannel listener) {
            listener.accept(listener, this); // get ready for next connection

            // callback 2
            BufChan.forTcp(sock).read(dnsSizeRead);
        }
    };

    private final FullReadCompletionHandler dnsRequestRead, dnsSizeRead;

    private final SocketAddress local;
    private boolean running = true;
    private Thread thisThread = null;

    public TcpAsync(final SocketAddress local, final Resolver resolver, final ExecutorService executor) {
        this.local = local;
        dnsRequestRead = new FullReadCompletionHandler() {
            @Override
            public void completed(final BufChan bc) {

                try {
                    bc.buf.flip();
                    //debugPacket(new Packet(bc.buf).getBuf());

                    try {
                        final byte[] interception = intercept(bc.buf.array(), local);
                        if (interception != null) {
                            final Packet responsePacket = new Packet(interception);
                            System.out.println("sending intercepted response");
                            writeResponse(bc, responsePacket);
                            System.out.println("*** SENT intercepted response");
                            return;
                        }
                    } catch (Exception e) {
                        System.err.println("Error processing interception: "+e);
                        e.printStackTrace();
                    }

                    resolver.resolveAsync(new Packet(bc.buf), executor).whenCompleteAsync((response, t) -> {
                        //System.out.println("got completed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
                        if(t != null) {
                            t.printStackTrace();
                            return;
                        }
                        //debugPacket(bc.getResponse().getBuf());

                        writeResponse(bc, response);
                    }, executor);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                BufChan.forTcp(bc.sock).read(dnsSizeRead);
            }
        };
        dnsSizeRead = bc -> {
            final int dnsPacketSize = Short.toUnsignedInt(bc.tcpHead.getShort(0));
            //System.out.println("dnsPacketSize: " + dnsPacketSize);
            bc.buf = ByteBuffer.allocate(dnsPacketSize);
            // read the actual packet
            bc.read(dnsRequestRead);
        };
    }

    protected byte[] intercept(byte[] buf, Object requestor) { return null; }

    private void writeResponse(BufChan bc, Packet response) {
        bc.tcpHead.clear();
        bc.tcpHead.putShort((short) response.getBuf().capacity());
        bc.tcpHead.rewind();
        bc.buf = bc.tcpHead;

        bc.write((FullWriteCompletionHandler) (bc2) -> {
            //System.out.println("header write complete");
            bc2.buf = response.getBuf();
            bc2.buf.rewind();
            bc2.write((FullWriteCompletionHandler) (unused) -> {
                //System.out.println("body write complete");
            });
        });
    }

    @Override
    public void run() {
        try (final AsynchronousServerSocketChannel listener = AsynchronousServerSocketChannel.open()) {

            listener.setOption(StandardSocketOptions.SO_REUSEADDR, true);
            listener.bind(local);

            listener.accept(listener, newConnection);
            thisThread = Thread.currentThread();
            while (running) Thread.sleep(Long.MAX_VALUE);

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            // just stop
        }
    }

    @Override
    public void close() {
        running = false;
        if (thisThread != null)
            thisThread.interrupt();
    }
}
