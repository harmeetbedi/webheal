package pcap.reconst.beans;

import java.net.InetAddress;

public class TcpConnection implements Comparable {
    private InetAddress srcIp;
    private int srcPort;
    private InetAddress dstIp;
    private int dstPort;

    public TcpConnection(TcpPacket packet) {
        srcIp = packet.getSourceIP();
        dstIp = packet.getDestinationIP();
        srcPort = packet.getSourcePort();
        dstPort = packet.getDestinationPort();
        //this.httpPort = httpPort;
        //flip();
    }
    public void flip() {
//        if ( srcPort < dstPort ) {
//            return;
//        }
        InetAddress tmpIp = srcIp;
        int tmpPort = srcPort;
        srcIp = dstIp;
        srcPort = dstPort;
        dstIp = tmpIp;
        dstPort = tmpPort;
    }

    public InetAddress getSrcIp() {
        return srcIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public InetAddress getDstIp() {
        return dstIp;
    }

    public int getDstPort() {
        return dstPort;
    }

    //ensures both request and response are reconstructed together
    public boolean equals(Object obj) {
        if (!(obj instanceof TcpConnection))
            return false;

        TcpConnection con = (TcpConnection) obj;

        return ((con.srcIp.equals(srcIp)) && (con.srcPort == srcPort) && (con.dstIp.equals(dstIp)) && (con.dstPort == dstPort)) ||
                ((con.srcIp.equals(dstIp)) && (con.srcPort == dstPort) && (con.dstIp.equals(srcIp)) && (con.dstPort == srcPort));

    }

    public int hashCode() {
        return ((srcIp.hashCode() ^ srcPort) ^
                ((dstIp.hashCode() ^ dstPort)));
    }

    @Override
    public String toString() {
        return String.format("%s.%s-%s.%s", srcIp.toString().replace("/", ""), srcPort, dstIp.toString().replace("/", ""), dstPort);
    }

/*
    public String getFileName(String path) {
        return String.format("%s%s.data", path, toString());
    }

*/
    public int compareTo(Object o) {
        if (!(o instanceof TcpConnection)) {
            return -1;
        }

        TcpConnection other = (TcpConnection) o;
        if (this.equals(other)) {
            return 0;
        }

        return getDstPort() * 2 + getSrcPort() - other.getSrcPort() * 2 + other.getDstPort();
//        if (getSrcPort() != httpPort && other.getSrcPort() != httpPort) {
//            return getSrcPort() - other.getSrcPort();
//        } else if (getDstPort() != httpPort && other.getDstPort() != httpPort) {
//            return getDstPort() - other.getDstPort();
//        } else {
//            return getDstPort() * 2 + getSrcPort() - other.getSrcPort() * 2 + other.getDstPort();
//        }
    }
}
