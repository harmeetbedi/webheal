package pcap.reconst.reconstructor;

import java.util.ArrayList;
import java.util.List;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import pcap.reconst.beans.JpcapTcpPacket;
import pcap.reconst.beans.TcpPacket;

public class JpcapPacketReceiver implements PacketReceiver {
    private int packetNumber = 0;
    private StreamReassembler packetReassembler;
    private final boolean verbose;
    private final boolean bufferPackets;
    private final List<TcpPacket> bufferedPackets = new ArrayList<TcpPacket>();

    public JpcapPacketReceiver(StreamReassembler packetReassembler,boolean bufferPackets, boolean verbose) {
        this.packetReassembler = packetReassembler;
        this.verbose = verbose;
        this.bufferPackets = bufferPackets;
    }

    public int getTotalNumberOfPackets() {
        return packetNumber;
    }

    public void flush() {
        packetReassembler.receivePackets(bufferedPackets);
        bufferedPackets.clear();
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
            JpcapTcpPacket jpkt = new JpcapTcpPacket(src);
            if ( bufferPackets ) {
                bufferedPackets.add(jpkt); 
            } else {
                packetReassembler.receivePacket(new JpcapTcpPacket(src));
            }
        }
    }
}

