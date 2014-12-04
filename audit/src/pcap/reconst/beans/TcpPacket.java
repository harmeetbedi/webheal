package pcap.reconst.beans;

import java.net.InetAddress;

public interface TcpPacket {
    InetAddress getSourceIP();
    int getSourcePort();
    InetAddress getDestinationIP();
    int getDestinationPort();
    int getCaptureLength();
    int getLength();
    int getHeaderLength();
    int getDataLength();
    long getSequence();
    long getAckNum();
    byte[] getData();
    boolean getSyn();
    boolean getFin();
}
