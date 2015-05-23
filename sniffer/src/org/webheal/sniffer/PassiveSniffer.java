package org.webheal.sniffer;

import java.io.File;
import java.io.IOException;
import java.util.Set;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import pcap.reconst.reconstructor.StreamReassembler;

public class PassiveSniffer extends AbstractSniffer implements Runnable
{
    private final String interfaceName;
    private final boolean pcapPktProcess;
    private final int pcapPktProcessCount;
    private final int pcapPktProcessTimeout;
    private final long streamProcessing;

    public PassiveSniffer(String interfaceName, Config conf, IHttpHandler handler) throws IOException {
        super(new StreamReassembler(conf.portFilter,conf.verbose), true, conf.hostFilter, conf.notExt, conf.notContentType, conf.traceDir, handler,conf.streamTimeout,conf.verbose);
        this.interfaceName = interfaceName;
        this.pcapPktProcess = conf.pcapPktProcess;
        this.pcapPktProcessCount = conf.pcapPktProcessCount;
        this.pcapPktProcessTimeout = conf.pcapPktProcessTimeout;
        this.streamProcessing = conf.streamProcessing;
    }
    public PassiveSniffer(String interfaceName, long maxIdleTime, Set<String> hostsFilter, Set<Integer> httpPort, Set<String> notExt, Set<String> notContentType, File tcpFlowDir, IHttpHandler handler, boolean verbose) throws IOException {
        super(new StreamReassembler(httpPort,verbose), true, hostsFilter, notExt, notContentType, tcpFlowDir, handler,maxIdleTime,verbose);
        
        this.interfaceName = interfaceName;
        this.pcapPktProcess = true;
        this.pcapPktProcessCount = 5000;
        this.pcapPktProcessTimeout = 3000;
        this.streamProcessing = 5*1000;
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
        //String filter = "tcp and ( port 80 ) and host 208.82.236.146"; //getTcpFilter();
        String filter = getTcpFilter();
        System.out.println("Selected interface : "+selected.name+", filter: "+filter);
        JpcapCaptor captor = JpcapCaptor.openDevice(selected, 65535, true, pcapPktProcessTimeout);
        captor.setFilter(filter, true);
        try { 
            if ( pcapPktProcess ) {
                while ( true ) {
                    int processedPackets = captor.processPacket(pcapPktProcessCount, jpcapProcessor);
                    if ( processedPackets > 0 ) {
                        System.out.println("processed packets : "+processedPackets);
                        jpcapProcessor.flush();
                    }
                    try {
                        Thread.currentThread().sleep(1000);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            } else {
                captor.loopPacket(-1, jpcapProcessor);
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
                Thread.currentThread().sleep(streamProcessing);
            } catch (InterruptedException e) {
                break;
            }
        }
    }
}
