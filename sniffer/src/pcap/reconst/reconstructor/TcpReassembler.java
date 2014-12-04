package pcap.reconst.reconstructor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.beans.TcpData;
import pcap.reconst.beans.TcpFragment;
import pcap.reconst.beans.TcpPacket;

public class TcpReassembler {
    private static final boolean TRACE = false;
    TcpData request;
    TcpData response;
    OutputStream outputStream = null;

    boolean incompleteTcpStream = false;
    boolean emptyTcpStream = true;
    private Payload payload = new Payload();

    public boolean isIncomplete() {
        return incompleteTcpStream;
    }

    public boolean isEmpty() {
        return emptyTcpStream;
    }

    public OutputStream getOutputStream() {
        return outputStream;
    }

    public Payload getPayload() {
        return payload;
    }

    public List<RequestResponse> getRequestResponse() {
        return payload.getRequestResponse();
    }

    public TcpReassembler() {
        outputStream = new ByteArrayOutputStream();
    }

    /*
     * The main function of the class receives a tcp packet and reconstructs the stream
     */
    public void reassemblePacket(TcpPacket tcpPacket) throws Exception {
        if ( TRACE ) System.out.println(String.format("captured_len = %d, len = %d, headerlen = %d, datalen = %d", tcpPacket.getCaptureLength(), tcpPacket.getLength(), tcpPacket.getHeaderLength(), tcpPacket.getDataLength()));
        long length = (long) (tcpPacket.getDataLength());
        //if (length == 0) {
        //    return;
        //}

        reassembleTcp(tcpPacket.getSequence(), tcpPacket.getAckNum(), length, tcpPacket.getData(), tcpPacket.getDataLength(), tcpPacket.getSyn(), new TcpConnection(tcpPacket));
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
    private void reassembleTcp(long sequence, long ack_num, long length, byte[] data, int dataLength, boolean synflag, TcpConnection tcpConnection) throws Exception {
        if ( TRACE ) System.out.println(String.format("sequence=%d ack_num=%d length=%d dataLength=%d synFlag=%s %s srcPort=%s %s dstPort=%s", sequence, ack_num, length, dataLength, synflag, tcpConnection.getSrcIp(), tcpConnection.getSrcPort(), tcpConnection.getDstIp(), tcpConnection.getDstPort()));

        boolean first = false;
        PacketType packetType = null;

        /* Now check if the packet is for this connection. */
        InetAddress srcIp = tcpConnection.getSrcIp();
        int srcPort = tcpConnection.getSrcPort();

        /* Check to see if we have seen this source IP and port before.
        /* check both source IP and port; the connection might be between two different ports on the same machine... */
        if (request == null) {
            request = new TcpData(srcIp, srcPort);
            packetType = PacketType.Request;
            first = true;
        } else {
            if (request.getAddress().equals(srcIp) && request.getPort() == srcPort) {
                // check if request is already being handled... this is a fragmented packet
                packetType = PacketType.Request;
            } else {
                if (response == null) {
                    response = new TcpData(srcIp, tcpConnection.getSrcPort());
                    packetType = PacketType.Response;
                    first = true;
                } else if (response.getAddress().equals(srcIp) && response.getPort() == srcPort) {
                    // check if response is already being handled... this is a fragmented packet
                    packetType = PacketType.Response;
                }
            }

        }

        if (packetType == null) {
            throw new Exception("ERROR in TcpReassembler: Too many or too few addresses!");
        }


        if (dataLength < length) {
            incompleteTcpStream = true;
        }

        if ( TRACE ) System.out.println(String.format("%s packet...", isRequest(packetType) ? "request" : "response"));
        TcpData current = isRequest(packetType) ? request : response;
        updateSequence(first, current, sequence, length, data, dataLength, synflag);
    }


    private boolean isRequest(PacketType packetType) {
        return PacketType.Request == packetType;
    }


    private void updateSequence(boolean first, TcpData tcpData, long sequence, long length, byte[] data, int data_length, boolean synflag) throws IOException {

        /* figure out sequence number stuff */
        if (first) {
            /* this is the first time we have seen this src's sequence number */
            tcpData.setSeq(sequence + length);
            if (synflag) {
                tcpData.incrementSeq();
            }
            /* write out the packet data */
            writePacketData(tcpData,data);
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
                writePacketData(tcpData,data);
            }
            /* done with the packet, see if it caused a fragment to fit */
            while (checkFragments(tcpData)) {
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
    private boolean checkFragments(TcpData tcpData) throws IOException {
        TcpFragment prev = null;
        TcpFragment current = tcpData.getFragment();

        while (current != null) {
            if (current.seq == tcpData.getSeq()) {
                /* this fragment fits the stream */
                if (current.data != null) {
                    writePacketData(tcpData,current.data);
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
    protected void writePacketData(TcpData tcpData, byte[] data) throws IOException {
        // ignore empty packets
        if (data.length == 0) return;
        Boolean req = isRequest(tcpData);
        if ( req == null ) {
            outputStream.write(data, 0, data.length);
        } else {
            payload.add(req,data);
        }
        emptyTcpStream = false;
    }
    
    protected Boolean isRequest(TcpData tcpData) {
        return null;
    }

    public static class Payload {
        LinkedList<RequestOrResponse> list = new LinkedList<RequestOrResponse>();
        void add(boolean request,byte[] data) {
            if ( list.size() == 0 ) {
                RequestOrResponse item = new RequestOrResponse(request,data);
                list.add(item);
            } else {
                RequestOrResponse last = list.get(list.size()-1);
                if ( last.request == request ) {
                    last.add(data);
                } else {
                    RequestOrResponse item = new RequestOrResponse(request,data);
                    list.add(item);
                }
            }
        }
        public List<RequestResponse> getRequestResponse() {
            List<RequestResponse> result = new ArrayList<RequestResponse>();
            // skip any initial response
            while ( !list.isEmpty() && list.get(0).isResponse() ) {
                list.remove(0);
            }
            if ( list.size() == 0 ) {
                return result;
            }
            RequestOrResponse lastRequest = null;
            for ( RequestOrResponse item : list ) {
                if ( lastRequest != null ) {
                    RequestResponse rr = new RequestResponse(lastRequest,item);
                    result.add(rr);
                    lastRequest = null;
                } else {
                    lastRequest = item;
                }
            }
            return result;
        }
    }
    public static class RequestResponse {
        public final RequestOrResponse request;
        public final RequestOrResponse response;
        RequestResponse(RequestOrResponse request,RequestOrResponse response) {
            this.request = request;
            this.response = response;
            //assert 
            if ( !( request.isRequest() && response.isResponse() ) ) {
                throw new RuntimeException("Invalid Request-Response pair - "+request.isRequest()+", "+response.isRequest());
            }
        }
    }
    public static class RequestOrResponse {
        private final boolean request;
        private final ByteArrayOutputStream out = new ByteArrayOutputStream ();
        public RequestOrResponse(boolean request, byte[] data) {
            this.request = request;
            try {
                out.write(data);
            } catch (IOException e) {
                e.printStackTrace();
            }
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
/*
    public String getOutputName() {
        StringBuilder sb = new StringBuilder();
        sb.append(request.getOutputName());
        sb.append("_");
        sb.append(response.getOutputName());
        return sb.toString();
    }
*/
}

