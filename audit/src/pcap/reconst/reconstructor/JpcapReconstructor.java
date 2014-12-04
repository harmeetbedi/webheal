package pcap.reconst.reconstructor;

import jpcap.JpcapCaptor;
import pcap.reconst.beans.TcpConnection;

import java.util.Map;

public class JpcapReconstructor implements Reconstructor {
    private PacketReassembler packetReassembler;

    public JpcapReconstructor(PacketReassembler packetReassembler) {
        this.packetReassembler = packetReassembler;
    }

    public Map<TcpConnection, TcpReassembler> reconstruct(String filename) throws Exception {
        System.out.println("reconstructing " + filename + " ...");
        JpcapCaptor captor = JpcapCaptor.openFile(filename);
        captor.setFilter("tcp", true);
        JpcapPacketProcessor jpcapPacketProcessor = new JpcapPacketProcessor(packetReassembler);
        captor.processPacket(-1, jpcapPacketProcessor);
        captor.close();
        return packetReassembler.getReassembledPackets();
    }

}
