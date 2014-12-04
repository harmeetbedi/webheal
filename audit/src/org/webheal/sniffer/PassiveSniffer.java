package org.webheal.sniffer;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Set;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.reconstructor.Reconstructor;
import pcap.reconst.reconstructor.TcpReassembler;

public class PassiveSniffer extends AbstractSniffer implements Runnable
{
    private final String interfaceName;

    public PassiveSniffer(String interfaceName, long maxIdleTime, Set<String> hostsFilter, Set<String> notExt, Set<String> notContentType, File tcpFlowDir, IHttpHandler handler) throws IOException {
        super(new TimedPacketReassembler(maxIdleTime), hostsFilter, notExt, notContentType, tcpFlowDir, handler);
        this.interfaceName = interfaceName;
    }
    public void init() throws IOException { 
        NetworkInterface[] nis = JpcapCaptor.getDeviceList();
        NetworkInterface selected = null;
        for ( NetworkInterface ni : nis ) {
            ///System.out.println("Found interface : "+ni.name);
            if ( ni.name.equals(interfaceName) ) {
                selected = ni;
            }
        }
        System.out.println("Selected interface : "+selected.name);
        JpcapCaptor captor = JpcapCaptor.openDevice(selected, 65535, true, 0);
        captor.setFilter("tcp port 80", true);
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
            } catch (IOException e1) {
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
