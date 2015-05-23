package org.webheal.sniffer;

import java.io.File;
import java.io.IOException;
import java.util.Set;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

import org.webheal.util.Utils;

import pcap.reconst.reconstructor.StreamReassembler;

public class PassiveSniffer extends AbstractSniffer implements Runnable
{
    private final String interfaceName;
    final boolean CAPTURE_LOOP = new Boolean(System.getProperty("pcap.loop", "false"));
    final int CAPTURE_PROCESS_TIMEOUT = (int)Utils.getTime(System.getProperty("pcap.pktread.timeout", "1s"));

    public PassiveSniffer(String interfaceName, long maxIdleTime, Set<String> hostsFilter, Set<Integer> httpPort, Set<String> notExt, Set<String> notContentType, File tcpFlowDir, IHttpHandler handler, boolean verbose) throws IOException {
        super(new StreamReassembler(httpPort,verbose), hostsFilter, notExt, notContentType, tcpFlowDir, handler,maxIdleTime,verbose);
        this.interfaceName = interfaceName;
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
        String filter = "tcp and ( port 80 ) and host 208.82.236.146"; //getTcpFilter();
        System.out.println("Selected interface : "+selected.name+", filter: "+filter);
        JpcapCaptor captor = JpcapCaptor.openDevice(selected, 65535, true, CAPTURE_PROCESS_TIMEOUT);
        captor.setFilter(filter, true);
        try { 
            if ( CAPTURE_LOOP ) {
                captor.loopPacket(-1, jpcapProcessor);
            } else {
                while ( true ) {
                    int processedPackets = captor.processPacket(100, jpcapProcessor);
                    if ( processedPackets > 0 ) {
                        System.out.println("processed packets : "+processedPackets);
                    }
                    try {
                        Thread.currentThread().sleep(5*1000);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            }
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
                Thread.currentThread().sleep(30*1000);
            } catch (InterruptedException e) {
                break;
            }
        }
    }
}
