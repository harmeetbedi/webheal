package pcap.reconst.output;

import java.io.File;
import java.io.IOException;
import java.net.HttpCookie;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.StringUtils;

import pcap.reconst.beans.InputData;
import pcap.reconst.beans.TcpConnection;

public class HttpRequestResponse {
    private String requestUri;
    private byte[] payload;
    private InputData request;
    private InputData response;
    public final TcpConnection conn;
    private byte[] requestUriBytes;
    private String method;
    private String host;

    public HttpRequestResponse(TcpConnection conn,String requestUri,byte[] requestUriBytes, byte[] payload, InputData request, InputData response) {
        //this.requestUri = requestUri;
        this.payload = payload;
        this.request = request;
        this.response = response;
        this.conn = conn;
        this.requestUriBytes = requestUriBytes;
    }

    public byte[] getPayload() {
        return payload;
    }

    public String getRequestUri() {
        if ( requestUri == null ) {
            Charset cs = request.getHeaders().getCharset();
            requestUri = new String(requestUriBytes,cs);
        }
        return requestUri;
    }
    public String getHost() {
        if ( host == null ) {
            host = request.getHost();
            if ( host == null ) {
                host = "";
            }
        }
        return host;
    }
    public byte[] getRequestUriBytes() {
        return requestUriBytes;
    }

    public InputData getRequest() {
        return request;
    }

    public InputData getResponse() {
        return response;
    }

    public void decode() {
        request.decode();
        response.decode();
    }
    
    public String getRequestMethod() {
        if ( method == null ) {
            method = request.getHeaders().getMethod();
        }
        return method;
    }

    public void writeToFile(File dir, String prefix, String seq) throws IOException
    {
        request.writeToFile(dir, prefix+".tx", seq);
        response.writeToFile(dir, prefix+".rx", seq);
    }

    public String getResponseStatus()
    {
        String line = response.getHeaders().getFirstKey();
        if ( line == null ) {
            return "";
        }
        String[] parts = line.split(" ");
        if ( parts.length >= 2 ) {
            return parts[1];
        }
        return "";
    }
    
    public List<HttpCookie> getRequestCookies() {
        String value = request.getHeaders().getValue("Cookie");
        if ( StringUtils.isEmpty(value)) {
            return new ArrayList<HttpCookie>();
        } else {
            return HttpCookie.parse(value); 
        }
    }
    
    public String toString() {
        int decSize = response.getDecodedDataSize();
        String msg = conn+", "+getHost()+", "+getRequestUri()+", req="+request.getDataSize()+", resp="+response.getDecodedDataSize();
        if ( decSize >= 0 ) {
            msg = msg + ", resp-decode="+decSize;
        }
        return msg;
    }
}
