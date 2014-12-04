package pcap.reconst.beans;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;

import org.apache.commons.httpclient.ChunkedInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import pcap.reconst.Utils;
import pcap.reconst.compression.CompressionType;
import pcap.reconst.compression.GzipZlibUtils;

public class InputData {
    private byte[] data;
    private byte[] decoded;
    private Headers headers;
    private Throwable decodeFailureReason;
    private String body;

    public InputData(byte[] data, Headers headers) {
        this.data = data;
        this.headers = headers;
    }

    public Headers getHeaders() {
        return headers;
    }

    public byte[] getData() {
        return data;
    }

    public int getDataSize() {
        return ( data == null ) ? -1 : data.length;
    }

    public int getDecodedDataSize() {
        return ( decoded == null ) ? -1 : data.length;
    }

    public byte[] getDecoded() {
        return decoded;
    }
    
    public Throwable getDecodeFailureReason() {
        return decodeFailureReason;
    }

    public int getInputLength() {
        return data.length;
    }

    public int getContentLength() {
        return headers.getContentLength();
    }

    public String getHost() {
        return headers.getHost();
    }

    public String getContentType() {
        return headers.getContentType();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (headers != null) {
            builder.append("Headers...\n");
            for (String name : headers.getNames()) {
                builder.append(String.format("%s: %s\n", name, headers.getValue(name)));
            }
        }
        builder.append(String.format("Encoded string: %s\n", new String(data)));
        return builder.toString();
    }

    public void printHex() {
        Utils.prettyPrintHex(data);
    }

    public boolean decode() {
        try {
            boolean chunked = headers.isChunked(); 
            CompressionType compressionType = headers.getCompressionType();
            boolean compressed = (compressionType != null );
            if ( !chunked && !compressed ) {
                return false;
            }
            byte[] todecode = data;
            if ( chunked ) {
                ByteArrayInputStream bin = new ByteArrayInputStream(data);
                ChunkedInputStream chunkedInp = new ChunkedInputStream(bin);
                ByteArrayOutputStream bout = new ByteArrayOutputStream();
                IOUtils.copy(chunkedInp, bout);
                todecode = bout.toByteArray();
            }
            this.decoded = GzipZlibUtils.uncompress(compressionType, todecode);
            return true;
        } catch(Throwable t) {
            decodeFailureReason = t;
            return false;
        }
    }
    
    public String getBody() {
        if  ( body != null ) {
            return body;
        }
        if ( data == null || data.length == 0 ) {
            body = "";
            return body;
        }
        if ( decodeFailureReason != null ) {
            body = "";
            return body;
        }
        byte[] bytes = data;
        if ( decoded != null ) {
            bytes = decoded;
        }
        Charset set = headers.getCharset();
        body = new String(bytes,set);
        return body;
    }

    public void writeToFile(File dir, String prefix, String seq) throws IOException
    {
        if ( data != null && data.length > 0 ) {
            FileUtils.writeByteArrayToFile(new File(dir,prefix+".B"+seq+".txt"), data);
        }
        FileUtils.writeStringToFile(new File(dir,prefix+".H"+seq+".txt"), headers.toString());
        if ( decoded != null && decoded.length > 0 ) {
            FileUtils.writeByteArrayToFile(new File(dir,prefix+".D"+seq+".txt"), decoded);
        }
        if ( decodeFailureReason != null ) {
            FileUtils.writeStringToFile(new File(dir,prefix+".E"+seq+".txt"), Utils.convert(decodeFailureReason));
        }
    }
}