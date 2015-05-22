package org.webheal.sniffer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Set;

import jpcap.JpcapCaptor;
import pcap.reconst.beans.TcpData;
import pcap.reconst.reconstructor.JpcapPacketProcessor;
import pcap.reconst.reconstructor.PacketReassembler;
import pcap.reconst.reconstructor.TcpReassembler;

public class PcapFileSniffer extends AbstractSniffer
{
    private final File src;

    public PcapFileSniffer(File src, Set<String> hostsFilter, Set<Integer> httpPort, Set<String> notExt, Set<String> notContentType, File tcpFlowDir, IHttpHandler handler,boolean verbose) throws IOException {
        super(new HttpPacketReassembler(httpPort), hostsFilter, notExt, notContentType, tcpFlowDir, handler,verbose);
        this.src = src;
    }

    public PcapFileSniffer(File src, Set<Integer> httpPort, IHttpHandler handler,boolean verbose) throws IOException {
        super(new HttpPacketReassembler(httpPort), handler,verbose);
        this.src = src;
    }

    @Override public void init() throws IOException
    {
        JpcapCaptor captor = JpcapCaptor.openFile(src.getAbsolutePath());
        captor.setFilter(getTcpFilter(), true);
        //captor.setFilter("tcp", true);
        JpcapPacketProcessor jpcapPacketProcessor = new JpcapPacketProcessor(pr,verbose);
        captor.processPacket(-1, jpcapPacketProcessor);
        captor.close();
    }
    private static class HttpPacketReassembler extends PacketReassembler {
        public HttpPacketReassembler(Set<Integer> httpPort) {
            super(httpPort);
        }

        @Override protected TcpReassembler newTcpReassembler() throws FileNotFoundException {
            return new TcpReassembler() {
                @Override protected Boolean isRequest(TcpData tcpData) {
                    return !httpPort.contains((int)tcpData.getPort());
                    //return ( tcpData.getPort() > 1024 );
                }
            };
        }
    }
}
