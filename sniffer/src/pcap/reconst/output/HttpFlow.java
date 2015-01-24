package pcap.reconst.output;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.httpclient.ChunkedInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import pcap.reconst.Utils;
import pcap.reconst.beans.Headers;
import pcap.reconst.beans.InputData;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.compression.Gunzip;
import pcap.reconst.decoder.Decoder;
import pcap.reconst.decoder.DecoderFactory;
import pcap.reconst.reconstructor.TcpReassembler;
import pcap.reconst.reconstructor.TcpReassembler.RequestResponse;

public class HttpFlow {
    private static Logger log = Logger.getLogger(Http.class);
    private static Logger SKIP_LOG = Logger.getLogger("skip");

    public static final String REQUEST_IDENTIFIER = " HTTP/1.";
    public static final String SEPARATOR = " ";
    public static final String RESPONSE_IDENTIFIER = "HTTP/1.";
    public static final byte[] REQUEST_IDENTIFIER_BYTES = REQUEST_IDENTIFIER.getBytes();
    public static final byte[] SEPARATOR_BYTES = SEPARATOR.getBytes();
    public static final byte[] RESPONSE_IDENTIFIER_BYTES = RESPONSE_IDENTIFIER.getBytes();

    public final static int ZERO = 0;

    public static Map<TcpConnection, List<HttpRequestResponse>> packetize(Map<TcpConnection, TcpReassembler> map, Set<String> hostsFilter, Set<String> ignoreUriExt, Set<String> ignoreContentType,boolean verbose) {
        Map<TcpConnection, List<HttpRequestResponse>> result = new HashMap<TcpConnection, List<HttpRequestResponse>>();
        for (TcpConnection connection : map.keySet()) {
            if ( verbose ) { System.out.println("HttpFlow conn: "+connection); }
            TcpReassembler reassembler = map.get(connection);
            List<RequestResponse> rrList = reassembler.getRequestResponse();
            if ( verbose ) { System.out.println("HttpFlow conn: "+connection+", rrList="+rrList.size()); }
            for ( RequestResponse rr : rrList ) {
                byte[] requestData = rr.request.toBytes();
                byte[] responseData = rr.response.toBytes();
                int requestIdx = Utils.getIndex(requestData, 0, 4*1024, REQUEST_IDENTIFIER_BYTES, true);
                int responseIdx = Utils.getIndex(responseData, 0, RESPONSE_IDENTIFIER_BYTES.length, RESPONSE_IDENTIFIER_BYTES, true);
                String requestUri = null;
                final int uriIndex = (requestIdx > 0) ? Utils.getIndex(requestData,0,requestIdx, SEPARATOR_BYTES, false) : -1;
                byte[] requestUriBytes = null;
                if ( uriIndex >= 0 ) {
                    requestUriBytes = Utils.slice(requestData,uriIndex+1,requestIdx-(uriIndex+1));
                    requestUri = new String(requestUriBytes);
                }
                if ( verbose ) { System.out.println(String.format("http packet : %s, request=%d, response=%d, uriIdx=%d, reqIdx=%d, respIdx=%d", connection, requestData.length, responseData.length, uriIndex, requestIdx, responseIdx)); }
                if ( requestUri == null || requestIdx < 0  || responseIdx != 0 ) {
//                    String reqStr = new String(requestData);
//                    String respStr = new String(responseData);
                    skipLog(String.format("Skipped http packet : %s, request=%d, response=%d, uriIdx=%d, reqIdx=%d, respIdx=%d", connection, requestData.length, responseData.length, uriIndex, requestIdx, responseIdx));
                    continue;
                }
                if( isIgnoreExt(requestUri,ignoreUriExt) ) {
                    skipLog(String.format("Skipped Request Uri : %s, req=%d, resp=%d, uri=%s", connection, requestData.length, responseData.length, requestUri));
                    continue;
                }
                InputData req = getData(requestData,true);
                String host = req.getHeaders().getHost();
                if( !isHostAllowed(host,hostsFilter) ) {
                    skipLog(String.format("Skipped Host : %s, req=%d, resp=%d, uri=%s, host=%s", connection, requestData.length, responseData.length, requestUri, host));
                    continue;
                }
                InputData resp = getData(responseData,true);
                String contentType = resp.getHeaders().getContentType();
                if( isIgnoreContentType(contentType,ignoreContentType) ) {
                    skipLog(String.format("Skipped Response ContentType : %s, req=%d, resp=%d, uri=%s, type=%s", connection, requestData.length, responseData.length, requestUri,contentType));
                    continue;
                }
                HttpRequestResponse http = new HttpRequestResponse(connection,requestUri,requestUriBytes, null, req, resp);
                Utils.add(result,connection, http);
            }
        }
        return result;
    }
    private static void skipLog(String msg) {
        System.out.println("SKIP: "+msg);
        SKIP_LOG.info(msg);
    }
    
    private static boolean isHostAllowed(String host, Set<String> hostsFilter)
    {
        if( hostsFilter == null || hostsFilter.size() == 0 ) {
            return true;
        }
        if ( StringUtils.isEmpty(host) ) {
            return false;
        }
        host = host.toLowerCase();
        for ( String item : hostsFilter ) {
            if ( host.contains(item)) {
                return true;
            }
        }
        return false;
    }
    private static boolean isIgnoreContentType(String contentType, Set<String> ignoreContentType)
    {
        if( ignoreContentType == null || ignoreContentType.size() == 0 ) {
            return false;
        }
        if ( StringUtils.isEmpty(contentType) ) {
            return false;
        }
        for ( String item : ignoreContentType ) {
            if ( contentType.contains(item)) {
                return true;
            }
        }
        return false;
    }
    private static boolean isIgnoreExt(String uri, Set<String> ignoreUriExt) {
        if( ignoreUriExt == null || ignoreUriExt.size() == 0 ) {
            return false;
        }
        int paramIdx = uri.lastIndexOf('?');
        if ( paramIdx > 0 ) {
            uri = uri.substring(0,paramIdx);
        }
        int extIdx = uri.lastIndexOf('.');
        if ( extIdx > 0 && (extIdx+1) < uri.length() ) {
            String ext = uri.substring(extIdx+1);
            ext = ext.toLowerCase();
            if ( ignoreUriExt.contains(ext) ) {
                return true;
            }
        }
        return false;
    }
    private static InputData getData(byte[] data, boolean sep) {
        if ( sep ) {
            return getHeaderBody(data);
        }
        String requestAsString = new String(data);
        Headers requestHeaders = getHeaders(requestAsString);
        log.debug(requestHeaders);
        int requestContentLength = requestHeaders.getContentLength();
        log.debug(requestContentLength);
        return new InputData(data, requestHeaders);
    }

    private static Headers getHeaders(String stringWithHeaders) {
        Headers headers = new Headers();
        String[] tokens = stringWithHeaders.split("\r\n");
        for (String token : tokens) {
            if (StringUtils.isEmpty(token)) {
                break;
            }
            String[] values = token.split(":");
            if ( values.length == 1 ) {
                headers.addHeader(token, "");
            } else {
                headers.addHeader(values[0], values[1]);
            }
        }
        return headers;
    }
    private static final byte[] HEADER_DELIM = "\r\n".getBytes();
    private static final byte[] HEADER_DELIM_NLONLY = "\n".getBytes();
    private static InputData getHeaderBody(byte[] data) {
        InputData result = getHeaderBody(data,false);
//        if ( result == null ) {
//            result = getHeaderBody(data,true);
//            String txt = new String(data);
//            System.out.println(txt);
//        }
        return result;
    }
    private static InputData getHeaderBody(byte[] data,boolean trace) {
        Headers headers = new Headers();
        int offset = readHeaders(data,0,headers,trace);
        if ( offset == -1 ) {
            return null;
        }
        byte[] body = Utils.slice(data, offset, data.length-offset);
        return new InputData(body, headers);
    }
    public static void main(String[] args) throws IOException {
        File file2 = new File("/Users/harmeet/tmp/sniffer/tcpflow/023.050.113.224.00080-192.168.000.012.59536");
        File file = new File("/Users/harmeet/tmp/sniffer/tcpflow/098.136.145.155.00080-192.168.000.012.59790");
        byte[] data = FileUtils.readFileToByteArray(file);
        InputData inp = getHeaderBody(data,true);
        ByteArrayInputStream bin = new ByteArrayInputStream(inp.getData());
        ChunkedInputStream chunked = new ChunkedInputStream(bin);
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        IOUtils.copy(chunked, bout);
        byte[] out = bout.toByteArray();
        File outFile = new File("/Users/harmeet/tmp/sniffer/chunked-"+System.currentTimeMillis());
        FileUtils.writeByteArrayToFile(outFile, out);
//        Decoder decoder = DecoderFactory.getDecoder();
//        decoder.decode(inp.getData(), inp.getHeaders());
        //byte[] unzip = new Gunzip(inp.getData()).unzip();
        byte[] unzip = new Gunzip(out).unzip();
        String full = new String(unzip);
        System.out.println("----------------------------------------------------------------------------------------------"); 
        System.out.println(full); 
        System.out.println("----------------------------------------------------------------------------------------------");
    }
    public static void main2(String[] args) throws IOException {
        File file = new File("/Users/harmeet/tmp/sniffer/test.txt");
        byte[] data = FileUtils.readFileToByteArray(file);
        int idx = Utils.getIndex(data, 334,data.length-334, HEADER_DELIM, true);
        byte[] data2 = Utils.slice(data, 334, data.length-334);
        int idx2 = Utils.getIndex(data2, 0,data.length, HEADER_DELIM, true);
        System.out.println("-- "+idx2);
        InputData result = getHeaderBody(data,true);
        System.out.println("-- "+(result != null));
    }
    private static int readHeaders(byte[] data, int offset, Headers headers,boolean trace) {
        boolean crlfSep = true;
        byte[] headerDelim = HEADER_DELIM;
        int idx = Utils.getIndex(data, offset, data.length - offset, headerDelim, true);
        if ( idx == -1 ) {
            headerDelim = HEADER_DELIM_NLONLY;
            crlfSep = false;
            idx = Utils.getIndex(data, offset, data.length - offset, headerDelim, true);
        }
        if ( trace ) System.out.println("Headers: "+data.length +", "+idx+", "+offset+", crlf:"+crlfSep);
        if ( idx == -1 ) {
            if ( trace ) {
                String txt = new String(Utils.slice(data, 0, data.length - offset));
                String full = new String(data);
                System.out.println("-- "+data.length+", "+offset); 
                System.out.println("----------------------------------------------------------------------------------------------"); 
                System.out.println(txt); 
                System.out.println("----------------------------------------------------------------------------------------------"); 
                System.out.println(full); 
                System.out.println("----------------------------------------------------------------------------------------------");
            }
            return -1;
        }
        if ( idx > offset ) {
            int len = idx - offset;
            String line = new String(Utils.slice(data, offset, len));
//            if ( line.charAt(line.length()-1) == '\r' ) {
//                line = line.substring(0,line.length()-1);
//            }
            if ( trace ) System.out.println("LINE (" +offset+","+idx+","+data.length+") > "+line);
            String[] values = line.split(":");
            if ( values.length == 1 ) {
                headers.addHeader(line, "");
            } else {
                headers.addHeader(values[0], values[1]);
            }
        }
        int newOffset = idx+headerDelim.length;
        if ( idx == offset ) {
            return newOffset; 
        } else {
            return readHeaders(data,newOffset,headers,trace);
        }
    }
}
