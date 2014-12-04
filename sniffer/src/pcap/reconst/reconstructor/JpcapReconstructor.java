package pcap.reconst.reconstructor;

import jpcap.JpcapCaptor;
import pcap.reconst.beans.TcpConnection;

import java.util.Map;

public class JpcapReconstructor implements Reconstructor {
    private PacketReassembler packetReassembler;
    private final boolean verbose;

    public JpcapReconstructor(PacketReassembler packetReassembler, boolean verbose) {
        this.packetReassembler = packetReassembler;
        this.verbose = verbose;
    }

    public Map<TcpConnection, TcpReassembler> reconstruct(String filename) throws Exception {
        System.out.println("reconstructing " + filename + " ...");
        JpcapCaptor captor = JpcapCaptor.openFile(filename);
        captor.setFilter("tcp", true);
        JpcapPacketProcessor jpcapPacketProcessor = new JpcapPacketProcessor(packetReassembler,verbose);
        captor.processPacket(-1, jpcapPacketProcessor);
        captor.close();
        return packetReassembler.getReassembledPackets();
    }

}
