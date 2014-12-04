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

    public PcapFileSniffer(File src, Set<String> hostsFilter, Set<String> notExt, Set<String> notContentType, File tcpFlowDir, IHttpHandler handler) throws IOException {
        super(new HttpPacketReassembler(), hostsFilter, notExt, notContentType, tcpFlowDir, handler);
        this.src = src;
    }

    public PcapFileSniffer(File src, IHttpHandler handler) throws IOException {
        super(new HttpPacketReassembler(), handler);
        this.src = src;
    }

    @Override public void init() throws IOException
    {
        JpcapCaptor captor = JpcapCaptor.openFile(src.getAbsolutePath());
        //captor.setFilter("tcp", true);
        JpcapPacketProcessor jpcapPacketProcessor = new JpcapPacketProcessor(pr);
        captor.processPacket(-1, jpcapPacketProcessor);
        captor.close();
    }
    private static class HttpPacketReassembler extends PacketReassembler {
        @Override protected TcpReassembler newTcpReassembler() throws FileNotFoundException {
            return new TcpReassembler() {
                @Override protected Boolean isRequest(TcpData tcpData) {
                    return ( tcpData.getPort() > 1024 );
                }
            };
        }
    }
}
