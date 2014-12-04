package org.webheal.sniffer;

import java.io.FileNotFoundException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.beans.TcpData;
import pcap.reconst.beans.TcpPacket;
import pcap.reconst.reconstructor.PacketReassembler;
import pcap.reconst.reconstructor.TcpReassembler;

public class TimedPacketReassembler extends PacketReassembler
{
    private Map<TcpConnection, Long> lastSeenMap = new HashMap<TcpConnection, Long>();
    private final long maxIdleTime;
    public TimedPacketReassembler(long maxIdleTime) {
        this.maxIdleTime = maxIdleTime;
    }
    @Override public synchronized void reassemble(TcpPacket tcpPacket)
    {
        super.reassemble(tcpPacket);
        TcpConnection c = new TcpConnection(tcpPacket);
        if (tcpPacket.getFin()) {
            //System.out.println("*** GOT_FIN : " + c);
            lastSeenMap.put(c, -1L);
        } else {
            lastSeenMap.put(c, System.currentTimeMillis());
        }
    }
    @Override public synchronized Map<TcpConnection, TcpReassembler> getReassembledPackets()
    {
        Map<TcpConnection, TcpReassembler> reassembledPackets = super.getReassembledPackets();
        Map<TcpConnection, TcpReassembler> result = new HashMap<TcpConnection, TcpReassembler>();
        int connCount = 0;
        int readyCount = 0;
        for (Map.Entry<TcpConnection, TcpReassembler> entry : reassembledPackets.entrySet()) {
            TcpConnection conn = entry.getKey();
            boolean ready = isReadyToProcess(conn);
            if (ready) {
                result.put(conn, entry.getValue());
                readyCount++;
            }
            connCount++;
        }
        for (TcpConnection c : result.keySet()) {
            reassembledPackets.remove(c);
        }
        //System.out.println((new Date()) +" : ready="+readyCount+", total="+connCount);
        return result;
    }

    private boolean isReadyToProcess(TcpConnection conn)
    {
        Long lastSeen = lastSeenMap.get(conn);
        if (lastSeen == null) {
            return true;
        }
        // assume connection is done if there is no activity for some time
        if (System.currentTimeMillis() - lastSeen > maxIdleTime) {
            return true;
        }
        return false;
    }
    @Override protected TcpReassembler newTcpReassembler() throws FileNotFoundException {
        return new TcpReassembler() {
            @Override protected Boolean isRequest(TcpData tcpData) {
                return ( tcpData.getPort() > 1024 );
            }
        };
    }
}
