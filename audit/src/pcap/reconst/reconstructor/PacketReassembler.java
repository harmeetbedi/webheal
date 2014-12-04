package pcap.reconst.reconstructor;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.beans.TcpPacket;

import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;

public class PacketReassembler {

    protected Map<TcpConnection, TcpReassembler> reassembledPackets = new HashMap<TcpConnection, TcpReassembler>();

    public Map<TcpConnection, TcpReassembler> getReassembledPackets() {
        return reassembledPackets;
    }

    public synchronized void reassemble(TcpPacket tcpPacket) {
        try {
            // Creates a key for the dictionary
            TcpConnection c = new TcpConnection(tcpPacket);

            // create a new entry if the key does not exists
            if (!reassembledPackets.containsKey(c)) {
                TcpReassembler tcpReassembler = newTcpReassembler();
                reassembledPackets.put(c, tcpReassembler);
            }

            // Use the TcpRecon class to reconstruct the session
            reassembledPackets.get(c).reassemblePacket(tcpPacket);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    protected TcpReassembler newTcpReassembler() throws FileNotFoundException {
        return new TcpReassembler();
    }
}
