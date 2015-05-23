package pcap.reconst.reconstructor;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.beans.TcpPacket;

public class StreamReassembler {

    // always remove and put into reassembledPackets. this ensures that old streams are always processed first
    protected Map<TcpConnection, TcpStream> reassembledPackets = new LinkedHashMap<TcpConnection, TcpStream>();
    
    protected Map<TcpConnection, TcpStream> completedStreams = new HashMap<TcpConnection, TcpStream>();
    
    protected final Set<Integer> httpPort;
    protected final boolean verbose;
    public StreamReassembler(Set<Integer> httpPort,boolean verbose) {
        this.httpPort = httpPort;
        this.verbose = verbose;
    }
    
    public Set<Integer> getHttpPort() { return httpPort; }

    public synchronized Map<TcpConnection, TcpStream> getCompletedStreams() {
        Map<TcpConnection, TcpStream> result = new LinkedHashMap<TcpConnection, TcpStream>();
        result.putAll(completedStreams);
        completedStreams.clear();
        return result;
    }

    public synchronized Map<TcpConnection, TcpStream> getTimeoutStreams(long timeout) {
        Map<TcpConnection, TcpStream> result = new LinkedHashMap<TcpConnection, TcpStream>(); 
        if ( timeout <= 0L ) {
            return result;
        }
        long now = System.currentTimeMillis();
        for ( Map.Entry<TcpConnection, TcpStream> entry :reassembledPackets.entrySet() ) {
            TcpConnection conn = entry.getKey();
            TcpStream reassembler = entry.getValue();
            if ( now - reassembler.getLastPacketTime() > timeout ) { 
                result.put(conn, entry.getValue());
            }
        }
        for ( TcpConnection conn : result.keySet() ) {
            reassembledPackets.remove(conn);
        }
        return result;
    }

    public synchronized void receivePacket(TcpPacket tcpPacket) {
        //System.out.println(tcpPacket);
        boolean request = httpPort.contains(tcpPacket.getDestinationPort());
        boolean response = httpPort.contains(tcpPacket.getSourcePort());
        if ( !request && !response ) {
            System.out.println("IGNORING DUE TO PORT : "+tcpPacket);
            return;
        }
        try {
            // Creates a key for the dictionary
            TcpConnection c = new TcpConnection(tcpPacket);
            if ( !request ) {
                c.flip();
            }
            TcpStream reassembler = reassembledPackets.remove(c);
            if( reassembler == null ) {
                // cannot start a new reassembler with response
                if( !request ) {
                    return;
                }
                // can only start a tcp reassember when syn is received
                if( !tcpPacket.getSyn() ) {
                    return;
                }
                reassembler = new TcpStream();
            }
            reassembledPackets.put(c, reassembler);
            reassembler.addPacket(request,tcpPacket);
            if( tcpPacket.getFin()) {
                // stream is complete
                completedStreams.put(c,reassembler);
                reassembledPackets.remove(c);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
