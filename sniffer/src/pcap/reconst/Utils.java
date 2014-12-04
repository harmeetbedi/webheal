package pcap.reconst;

import org.apache.log4j.Logger;
import pcap.reconst.beans.Headers;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.compression.CompressionType;
import pcap.reconst.output.HttpDecodedOutput;

import java.io.*;
import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class Utils extends org.webheal.util.Utils {
    private static Logger log = Logger.getLogger(Utils.class);

    public static Headers getHttpHeaders(HttpURLConnection con) {
        Headers headers = new Headers();
        for (int i = 0; ; i++) {
            String headerName = con.getHeaderFieldKey(i);
            String headerValue = con.getHeaderField(i);

            if (headerName == null && headerValue == null) {
                break;
            }
            headers.addHeader(headerName, headerValue);
        }
        return headers;
    }

    public static void prettyPrintHex(byte[] data) {
        int i = 0;
        int j = 0;
        int lineAddr = 0;
        if (data.length == 0) {
            return;
        }

        StringBuilder stringBuilder = new StringBuilder();
        //Loop through every input byte
        String hexline = "";
        String asciiline = "";
        for (i = 0, lineAddr = 0; i < data.length; i++, lineAddr++) {
            //Print the line numbers at the beginning of the line
            if ((i % 16) == 0) {
                if (i != 0) {
                    stringBuilder.append(hexline);
                    stringBuilder.append("\t...\t");
                    stringBuilder.append(asciiline + "\n");
                }
                asciiline = "";
                hexline = String.format("%#06x ", lineAddr);
            }
            hexline = hexline.concat(String.format("%#04x ", data[i]));
            if (data[i] > 31 && data[i] < 127) {
                asciiline = asciiline.concat(String.valueOf((char) data[i]));
            } else {
                asciiline = asciiline.concat(".");
            }
        }
        // Handle the ascii for the final line, which may not be completely filled.
        if (i % 16 > 0) {
            for (j = 0; j < 16 - (i % 16); j++) {
                hexline = hexline.concat("     ");
            }
            stringBuilder.append(hexline);
            stringBuilder.append("\t...\t");
            stringBuilder.append(asciiline);
        }
        log.debug(stringBuilder.toString());
    }

    public static byte[] intToByteArray(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value};
    }

    public static boolean isCompressed(CompressionType compressionType) {
        boolean isCompressed = false;
        if (compressionType != null) {
            isCompressed = true;
        }
        return isCompressed;
    }

    public static byte[] slice(byte[] src, int offset, int len)
    {
        byte[] dest = new byte[len];
        System.arraycopy(src, offset, dest, 0, len);
        return dest;
    }

    public static<X,Y> void add(Map<X, List<Y>> map, X key, Y value)
    {
        List<Y> list = map.get(key);
        if ( list == null ) {
            list = new ArrayList<Y>();
            map.put(key,list);
        }
        list.add(value);
    }
}
