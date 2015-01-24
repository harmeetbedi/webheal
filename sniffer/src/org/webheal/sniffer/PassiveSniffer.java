package org.webheal.sniffer;

import java.io.File;
import java.io.IOException;
import java.util.Set;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class PassiveSniffer extends AbstractSniffer implements Runnable
{
    private final String interfaceName;
    private int httpPort;

    public PassiveSniffer(String interfaceName, long maxIdleTime, Set<String> hostsFilter, int httpPort, Set<String> notExt, Set<String> notContentType, File tcpFlowDir, IHttpHandler handler, boolean verbose) throws IOException {
        super(new TimedPacketReassembler(httpPort,maxIdleTime), hostsFilter, notExt, notContentType, tcpFlowDir, handler,verbose);
        this.interfaceName = interfaceName;
        this.httpPort = httpPort;
    }
    public void init() throws IOException { 
        NetworkInterface[] nis = JpcapCaptor.getDeviceList();
        NetworkInterface selected = null;
        for ( NetworkInterface ni : nis ) {
            System.out.println("Found interface : "+ni.name);
            if ( ni.name.equals(interfaceName) ) {
                selected = ni;
            }
        }
        System.out.println("Selected interface : "+selected.name);
        JpcapCaptor captor = JpcapCaptor.openDevice(selected, 65535, true, 0);
        captor.setFilter("tcp port "+httpPort, true);
        try {
            captor.loopPacket(-1, jpcapProcessor);
        } finally {
            captor.close();
        }
    }
    
    public void run() {
        while ( true ) {
            try {
                drainPackets();
            } catch (Throwable e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
            try {
                Thread.currentThread().sleep(5*1000);
            } catch (InterruptedException e) {
                break;
            }
        }
    }
}
