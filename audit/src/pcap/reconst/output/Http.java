package pcap.reconst.output;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import pcap.reconst.Utils;
import pcap.reconst.beans.Headers;
import pcap.reconst.beans.InputData;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.reconstructor.TcpReassembler;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.util.*;

public class Http {
    private static Logger log = Logger.getLogger(Http.class);

    public static final String REQUEST_IDENTIFIER = " HTTP/1.1";
    public static final String SEPARATOR = " ";
    public static final String RESPONSE_IDENTIFIER = "HTTP/1.1 ";
    public static final byte[] REQUEST_IDENTIFIER_BYTES = REQUEST_IDENTIFIER.getBytes();
    public static final byte[] SEPARATOR_BYTES = SEPARATOR.getBytes();
    public static final byte[] RESPONSE_IDENTIFIER_BYTES = RESPONSE_IDENTIFIER.getBytes();

    public final static int ZERO = 0;
    private boolean hasRequestData = false;
    private boolean hasResponseData = false;
    private String requestUri;


    private Map<TcpConnection, TcpReassembler> map;

    public Http(Map<TcpConnection, TcpReassembler> map) {
        this.map = map;
    }

    public Map<TcpConnection, List<HttpRequestResponse>> packetize() {
        Set<TcpConnection> connections = map.keySet();
        SortedSet<TcpConnection> sortedConnections = new TreeSet(new Comparator<TcpConnection>() {
            public int compare(TcpConnection one, TcpConnection two) {
                return one.compareTo(two);
            }
        });
        sortedConnections.addAll(connections);
        log.debug(connections);
        log.debug(sortedConnections);

        Map<TcpConnection, List<HttpRequestResponse>> httpPackets = new HashMap<TcpConnection, List<HttpRequestResponse>>();
        for (TcpConnection connection : sortedConnections) {
            TcpReassembler reassembler = map.get(connection);
            ByteArrayOutputStream outputStream = (ByteArrayOutputStream) reassembler.getOutputStream();
            byte[] bytes = outputStream.toByteArray();
            String bytesAsString = new String(bytes);
            if (bytesAsString.indexOf("HTTP/1") > -1) {
                System.out.println(String.format(">>>>>> http packet........ %s", connection));
                try {
                    HttpRequestResponse httpOutput = toHttp(bytes);
                    Utils.add(httpPackets,connection, httpOutput);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return httpPackets;
    }

    public HttpRequestResponse toHttp(byte[] byteArray) throws FileNotFoundException {
        log.debug(String.format("total length %d\n", byteArray.length));
        //String byteArrayAsString = new String(byteArray);
//        final int requestIndex = byteArrayAsString.indexOf(REQUEST_IDENTIFIER);
//        final int responseIndex = byteArrayAsString.indexOf(RESPONSE_IDENTIFIER);
        final int requestIndex = Utils.getIndex(byteArray, REQUEST_IDENTIFIER_BYTES);
        final int uriIndex = (requestIndex > 0) ? Utils.getIndex(byteArray,0,requestIndex, SEPARATOR_BYTES, false) : -1;
        final int responseIndex = Utils.getIndex(byteArray, RESPONSE_IDENTIFIER_BYTES);
        byte[] requestUriBytes = null;
        if (requestIndex > -1 && uriIndex > -1 ) {
            hasRequestData = true;
            requestUriBytes = Utils.slice(byteArray,uriIndex+1,requestIndex-(uriIndex+1));
            this.requestUri = new String(requestUriBytes);
        }
        if (responseIndex > -1 ) {
            hasResponseData = true;
        }

        if (hasRequestData) {
            InputData request;
            InputData response = null;

            if (hasResponseData) {
                request = getRequest(byteArray, responseIndex);
                int responseLength = byteArray.length - responseIndex;
                response = getResponse(byteArray, responseLength, responseIndex);
//                
//                if ( responseIndex >= 0 ) {
//                    request = getRequest(byteArray, responseIndex);
//                    int responseLength = byteArray.length - responseIndex;
//                    response = getResponse(byteArray, responseLength, responseIndex);
//                } else {
//                    response = getResponse(byteArray, 0,byteArray.length);
//                }
            } else {
                request = getRequest(byteArray, byteArray.length);
            }

            return new HttpRequestResponse(null,requestUri,requestUriBytes, byteArray, request, response);
        }
        return null;
    }

    private InputData getResponse(byte[] byteArray, int responseLength, int responseIndex) {
        byte[] response = new byte[responseLength];
        System.arraycopy(byteArray, responseIndex, response, ZERO, responseLength);
        String responseAsString = new String(response);
        Headers responseHeaders = getHeaders(responseAsString);
        log.debug(responseHeaders);
        int responseContentLength = responseHeaders.getContentLength();
        log.debug(responseContentLength);
        return new InputData(response, responseHeaders);
    }

    private InputData getRequest(byte[] byteArray, int responseIndex) {
        byte[] request = new byte[responseIndex];
        System.arraycopy(byteArray, ZERO, request, ZERO, responseIndex);
        String requestAsString = new String(request);
        Headers requestHeaders = getHeaders(requestAsString);
        log.debug(requestHeaders);
        int requestContentLength = requestHeaders.getContentLength();
        log.debug(requestContentLength);
        return new InputData(request, requestHeaders);
    }

    private static Headers getHeaders(String stringWithHeaders) {
        Headers headers = new Headers();
        String[] tokens = stringWithHeaders.split("\r\n");
        for (String token : tokens) {
            if (StringUtils.isEmpty(token)) {
                break;
            }
            if (token.contains(": ")) {
                String[] values = token.split(": ");
                headers.addHeader(values[0], values[1]);
            }
        }
        return headers;
    }
}
