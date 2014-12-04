package pcap.reconst.beans;

import org.apache.commons.lang.StringUtils;
import pcap.reconst.compression.CompressionType;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class Headers {
    public static final String CONTENT_LENGTH = "Content-Length";
    public static final String CONTENT_TYPE = "Content-Type";
    public static final String HOST = "Host";
    public static final String CONTENT_ENCODING = "Content-Encoding";
    public static final String ACCEPT_ENCODING = "Accept-Encoding";
    public static final String GZIP = "gzip";
    public static final String DICT = "dict";
    public static final String DEFLATE = "deflate";
    public static final String TRANSFER_ENCODING = "Transfer-Encoding";

    private LinkedHashMap<String, String> headers;
    private CompressionType compressionType;
    private Charset charset;

    public Headers() {
        headers = new LinkedHashMap<String, String>();
    }

    public Map<String,String> getMap() {
        return headers;
    }
    public void addHeader(String name, String value) {
        while ( value.startsWith(" ")) {
            value = value.substring(1);
        }
        headers.put(name, value);
    }

    public Set<String> getNames() {
        return headers.keySet();
    }

    public String getValue(String name) {
        return headers.get(name);
    }

    public boolean hasHeader(String key) {
        return headers.keySet().contains(key);
    }

    public boolean checkIfExistsWithNonEmptyValue(String tag) {
        if (hasHeader(tag)) {
            String value = getValue(tag);
            return StringUtils.isNotEmpty(value);
        }
        return false;
    }

    public String getIfExistsWithNonEmptyValue(String tag) {
        if (hasHeader(tag)) {
            String value = getValue(tag);
            if (StringUtils.isNotEmpty(value)) {
                return value;
            }
        }
        return null;
    }
    
    public String getMethod() {
        String key = getFirstKey();
        if ( key != null ) {
            int idx = key.indexOf(' ');
            if ( idx > 0 ) {
                return key.substring(0,idx);
            }
        }
        return null;
    }

    public String getFirstKey() { 
        for ( Map.Entry<String,String> entry : headers.entrySet() ) {
            return entry.getKey();
        }
        return null;
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter prt = new PrintWriter(str,true);
        boolean first = true;
        for ( Map.Entry<String, String> entry : headers.entrySet() ) {
            String value = entry.getValue();
            if ( first && StringUtils.isEmpty(value)) {
                prt.println(entry.getKey());
            } else {
                prt.println(entry.getKey()+": "+value);
            }
            first = false;
        }
        prt.flush();
        return str.toString();
        //return headers.toString();
    }

    public int getContentLength() {
        String contentLength = getValue(CONTENT_LENGTH);
        if (StringUtils.isNumeric(contentLength)) {
            return Integer.parseInt(contentLength);
        }
        return 0;
    }
    
    public boolean isChunked() {
        String value = getValue(TRANSFER_ENCODING);
        return ( value != null && value.equals("chunked"));
    }

    public String getContentType() {
        return getValue(CONTENT_TYPE);
    }

    public Charset getCharset() {
        if ( charset != null ) {
            return charset;
        }
        charset = Charset.defaultCharset();
        String type = getContentType();
        if ( type != null ) {
            String[] parts = type.split(";");
            for ( String part : parts ) {
                if ( part.toLowerCase().startsWith("charset")) {
                    String[] ctParts = part.split("=");
                    if ( ctParts.length > 1 ) {
                        String ct = ctParts[1].toUpperCase();
                        try {
                            charset = Charset.forName(ct);
                        } catch(Throwable t) { }
                    }
                    break;
                }
            }
        }
        return charset;
    }

    public String getHost() {
        return getValue(HOST);
    }

    public CompressionType getCompressionType() {
        String contentEncoding = getValue(Headers.CONTENT_ENCODING);
        if (StringUtils.isNotEmpty(contentEncoding) && CompressionType.isValid(contentEncoding)) {
            compressionType = CompressionType.valueOf(contentEncoding);
        }
        return compressionType;
    }

    public String getRequestUri()
    {
        //headers.
        return null;
    }
}
