package pcap.reconst.reconstructor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.beans.TcpState;
import pcap.reconst.beans.TcpFragment;
import pcap.reconst.beans.TcpPacket;

// reassembels tcp packets for one connection
public class TcpStream {
    private static final boolean TRACE = false;
    private long lastPacketTime = -1L;

    boolean incompleteTcpStream = false;
    boolean emptyTcpStream = true;
    private Payload payload = new Payload();
    private TcpState requestState;
    private TcpState responseState;

    public boolean isIncomplete() {
        return incompleteTcpStream;
    }

    public boolean isEmpty() {
        return emptyTcpStream;
    }

    public Payload getRequestResponse() {
        return payload;
    }

    /*
     * The main function of the class receives a tcp packet and reconstructs the stream
     */
    public void addPacket(boolean requestPacketType, TcpPacket tcpPacket) throws Exception {
        lastPacketTime = System.currentTimeMillis();
        if ( TRACE ) System.out.println(String.format("captured_len = %d, len = %d, headerlen = %d, datalen = %d", tcpPacket.getCaptureLength(), tcpPacket.getLength(), tcpPacket.getHeaderLength(), tcpPacket.getDataLength()));
        long length = (long) (tcpPacket.getDataLength());
        //if (length == 0) {
        //    return;
        //}

        reassembleTcp(requestPacketType,tcpPacket.getSequence(), tcpPacket.getAckNum(), length, tcpPacket.getData(), tcpPacket.getDataLength(), tcpPacket.getSyn(), tcpPacket.getSourceIP(), tcpPacket.getSourcePort());
    }
    
    // time when last packet was added
    public long getLastPacketTime() {
        return lastPacketTime;
    }


    /*
    * Reconstructs the tcp session
    * @param sequence Sequence number of the tcp packet
    * @param length The size of the original packet data
    * @param data The captured data
    * @param data_length The length of the captured data
    * @param synflag
    * @param net_src The source ip address
    * @param net_dst The destination ip address
    * @param srcport The source port
    * @param dstport The destination port
    */
    private void reassembleTcp(boolean requestPacketType, long sequence, long ack_num, long length, byte[] data, int dataLength, boolean synflag,InetAddress srcIp,int srcPort) throws Exception {
        if ( TRACE ) System.out.println(String.format("sequence=%d ack_num=%d length=%d dataLength=%d synFlag=%s src=%s %d", sequence, ack_num, length, dataLength, synflag, srcIp.getHostAddress(), srcPort));

        /* Check to see if we have seen this source IP and port before.
        /* check both source IP and port; the connection might be between two different ports on the same machine... */
        boolean first = false;
        if ( requestPacketType && (requestState == null) ) {
            requestState = new TcpState(srcIp, srcPort);
            first = true;
        }
        if ( !requestPacketType && (responseState == null) ) {
            responseState = new TcpState(srcIp, srcPort);
            first = true;
        }
        TcpState current = requestPacketType ? requestState : responseState;

        if (dataLength < length) {
            incompleteTcpStream = true;
        }

        if ( TRACE ) System.out.println(String.format("%s packet...", requestPacketType ? "request" : "response"));
        updateSequence(requestPacketType,first, current, sequence, length, data, dataLength, synflag);
    }


    private void updateSequence(boolean requestPacketType, boolean first, TcpState tcpData, long sequence, long length, byte[] data, int data_length, boolean synflag) throws IOException {

        /* figure out sequence number stuff */
        if (first) {
            /* this is the first time we have seen this src's sequence number */
            tcpData.setSeq(sequence + length);
            if (synflag) {
                tcpData.incrementSeq();
            }
            /* write out the packet data */
            writePacketData(requestPacketType,data);
            return;
        }

        long newseq;
        /* if we are here, we have already seen this src, let's try and figure out if this packet is in the right place */
        if (sequence < tcpData.getSeq()) {
            /* this sequence number seems dated, but check the end to make sure it has no more info than we have already seen */
            if ( TRACE ) System.out.println("sequence number is less than tcpData's seq number");
            newseq = sequence + length;
            if (newseq > tcpData.getSeq()) {
                int new_len;

                /* this one has more than we have seen. let's get the payload that we have not seen. */
                new_len = (int) (tcpData.getSeq() - sequence);

                if (data_length <= new_len) {
                    data = null;
                    data_length = 0;
                    incompleteTcpStream = true;
                } else {
                    data_length -= new_len;
                    byte[] tmpData = new byte[data_length];
                    System.arraycopy(data, new_len, tmpData, 0, data_length);

                    data = tmpData;
                }
                sequence = tcpData.getSeq();
                length = newseq - tcpData.getSeq();
            }
        }

        if (sequence == tcpData.getSeq()) {
            /* packet in sqeuence */
            tcpData.addToSeq(length);
            if (synflag) {
                tcpData.incrementSeq();
            }
            if (data != null) {
                writePacketData(requestPacketType,data);
            }
            /* done with the packet, see if it caused a fragment to fit */
            while (checkFragments(requestPacketType,tcpData)) {
            }
        } else {
            TcpFragment tempFragment;
            /* out of order packet */
            if (data_length > 0 && sequence > tcpData.getSeq()) {
                tempFragment = new TcpFragment();
                tempFragment.data = data;
                tempFragment.seq = sequence;
                tempFragment.len = length;
                tempFragment.data_len = data_length;

                if ( TRACE ) System.out.println("out of seq...");
                if (tcpData.getFragment() != null) {
                    tempFragment.next = tcpData.getFragment();
                } else {
                    tempFragment.next = null;
                }
                tcpData.setFragment(tempFragment);
            }
        }
    } /* end reassemble_tcp */

    /* here we search through all the frag we have collected to see if one fits */
    private boolean checkFragments(boolean requestPacketType,TcpState tcpData) throws IOException {
        TcpFragment prev = null;
        TcpFragment current = tcpData.getFragment();

        while (current != null) {
            if (current.seq == tcpData.getSeq()) {
                /* this fragment fits the stream */
                if (current.data != null) {
                    writePacketData(requestPacketType,current.data);
                }
                tcpData.addToSeq(current.len);
                if (prev != null) {
                    prev.next = current.next;
                } else {
                    tcpData.setFragment(current.next);
                }
                current.data = null;
                return true;
            }
            prev = current;
            current = current.next;
        }
        return false;
    }

    //private void writePacketData(int index, byte[] data) throws IOException {
    private void writePacketData(boolean requestPacketType,byte[] data) throws IOException {
        // ignore empty packets
        if (data.length == 0) return;
        //System.out.println((req ? " > ":" < ")+tcpData.getAddress().getHostAddress()+":"+tcpData.getPort()+", "+data.length);
        payload.add(requestPacketType,data);
        emptyTcpStream = false;
    }
    
    public static class Payload {
        public final RequestOrResponse request = new RequestOrResponse (true);
        public final RequestOrResponse response = new RequestOrResponse (false);
        void add(boolean request,byte[] data) {
            if ( request ) {
                this.request.add(data);
            } else {
                this.response.add(data);
            }
        }
        public String toString() {
            return "req="+request.out.size()+", resp="+response.out.size();
        }
    }
    public static class RequestOrResponse {
        private final boolean request;
        private final ByteArrayOutputStream out = new ByteArrayOutputStream ();
        public RequestOrResponse(boolean request) {
            this.request = request;
        }
        void add(byte[] data) {
            try {
                out.write(data);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        boolean isRequest() {
            return request;
        }
        boolean isResponse() {
            return !request;
        }
        public byte[] toBytes() {
            return out.toByteArray();
        }
    }
}

