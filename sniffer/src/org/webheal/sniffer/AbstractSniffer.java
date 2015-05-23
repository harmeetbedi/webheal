package org.webheal.sniffer;

import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpFlow;
import pcap.reconst.output.HttpRequestResponse;
import pcap.reconst.reconstructor.JpcapPacketProcessor;
import pcap.reconst.reconstructor.StreamReassembler;
import pcap.reconst.reconstructor.TcpStream;

public abstract class AbstractSniffer
{
    protected final StreamReassembler pr;
    protected final JpcapPacketProcessor jpcapProcessor;
    protected final File tcpFlowDir;
    protected final Set<String> notExt;
    protected final Set<String> notContentType;
    protected final Set<String> hostsFilter;
    protected final IHttpHandler handler;
    protected final boolean verbose;
    private final long streamTimeout;
    private static DateFormat TIME_FMT = new SimpleDateFormat("yyMMddHHss");
    private static NumberFormat SEQ_FMT = new DecimalFormat("000");

    public AbstractSniffer(StreamReassembler pr, boolean bufferPackets, Set<String> hostsFilter, Set<String> notExt, Set<String> notContentType, File tcpFlowDir, IHttpHandler handler, long timeout, boolean verbose) throws IOException {
        this.notExt = notExt;
        this.notContentType = notContentType;
        this.hostsFilter = hostsFilter;
        this.tcpFlowDir = tcpFlowDir;
        this.pr = pr;
        jpcapProcessor = new JpcapPacketProcessor(pr,bufferPackets,verbose);
        this.handler = handler;
        this.verbose = verbose;
        this.streamTimeout = timeout;
    }

    public abstract void init() throws IOException; 
    
    public void drainPackets() throws IOException {
        processConnections(pr.getCompletedStreams());
        processConnections(pr.getTimeoutStreams(streamTimeout));
    }
    
    protected void processConnections(Map<TcpConnection, TcpStream> map) throws IOException {
        if ( map.size() == 0 ) { 
            return;
        }
        if ( verbose ) {
            System.out.println("Connections to process = " + map.size());
        }
        Map<TcpConnection, List<HttpRequestResponse>> httpPackets = HttpFlow.packetize(map,hostsFilter,notExt,notContentType,verbose);
        System.out.println("httpstreams to process = " + httpPackets.size());
        String dt = TIME_FMT.format(new Date());
        for ( Map.Entry<TcpConnection, List<HttpRequestResponse>> entry : httpPackets.entrySet() ) {
            String conn = entry.getKey().toString();
            if ( verbose ) System.out.println("Processing " + conn);
            int idx = 0;
            for ( HttpRequestResponse http : entry.getValue() ) {
                idx++;
                String seq = SEQ_FMT.format(idx);
                http.getRequest().decode();
                http.getResponse().decode();
                if ( verbose ) System.out.println("Processing " + http.getHost()+", "+http.getRequestUri()+", inplen:"+http.getRequest().getDataSize()+", outlen:"+http.getResponse().getDataSize());
                //System.out.println("Processing " + http.getHost()+", "+http.getRequestUri()+", inp:"+http.getRequest()+", out:"+http.getResponse());
                if ( tcpFlowDir != null ) {
                    http.writeToFile(tcpFlowDir,conn+"."+dt,seq);
                }
                try {
                    handler.handleHttp(entry.getKey(), http);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    protected String getDstPortFilter() {
        StringBuffer buf = new StringBuffer();
        boolean first = true;
        for ( int port : pr.getHttpPort() ) {
            if ( first ) {
                first = false;
            } else {
                buf.append(" or ");
            }
            buf.append(port+"");
        }
        return buf.toString();
    }
    protected String getTcpFilter() {
        return "tcp and ( port "+getDstPortFilter()+" )";
    }
}
