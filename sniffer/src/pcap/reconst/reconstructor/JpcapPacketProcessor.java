package pcap.reconst.reconstructor;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import pcap.reconst.beans.JpcapTcpPacket;

public class JpcapPacketProcessor implements PacketReceiver {
    int packetNumber = 0;
    private StreamReassembler packetReassembler;
    private final boolean verbose;

    public JpcapPacketProcessor(StreamReassembler packetReassembler,boolean verbose) {
        this.packetReassembler = packetReassembler;
        this.verbose = verbose;
    }

    public int getTotalNumberOfPackets() {
        return packetNumber;
    }

    //this method is called every time Jpcap captures a packet
    public void receivePacket(Packet packet) {
        packetNumber++;
        if ( verbose ) System.out.println("packet > "+packetNumber +" > "+packet);
        if ( packet instanceof TCPPacket) {
            TCPPacket src = (TCPPacket) packet;
            if ( src.src_ip == null ) {
                if ( verbose ) System.out.println(String.format("ignorning invalid #%d %s", packetNumber, src));
                return;
            }
            if ( verbose ) System.out.println(String.format("processing #%d %s", packetNumber, src));
            packetReassembler.receivePacket(new JpcapTcpPacket(src));
        }
    }
}

