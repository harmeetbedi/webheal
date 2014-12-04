package pcap.reconst.decoder;

import org.apache.log4j.Logger;
import pcap.reconst.Utils;
import pcap.reconst.beans.DecodedData;
import pcap.reconst.beans.Headers;
import pcap.reconst.compression.CompressionType;
import pcap.reconst.compression.GzipZlibUtils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

public class DecoderImpl implements Decoder {

    private static Logger log = Logger.getLogger(DecoderImpl.class);

    public DecodedData decode(byte[] streamToBeDecoded, Headers headers) {
        log.debug(String.format("length is [%d], data is [%s]", streamToBeDecoded.length, new String(streamToBeDecoded)));
        Utils.prettyPrintHex(streamToBeDecoded);

        if (headers != null) {
            CompressionType compressionType = headers.getCompressionType();
            if (Utils.isCompressed(compressionType)) {
                streamToBeDecoded = GzipZlibUtils.uncompress(compressionType, streamToBeDecoded);
                //String txt = new String(streamToBeDecoded);
                log.debug(String.format("after gunzip: length is [%d], data is [%s]", streamToBeDecoded.length, new String(streamToBeDecoded)));
            }
        }
        return new DecodedData(streamToBeDecoded, headers);
    }

    public static void main(String[] args) throws FileNotFoundException {
        DecoderImpl decoder = new DecoderImpl();
        FileInputStream fis = new FileInputStream("c:\\wireshark\\http.reconst");
        byte[] byteArray = Utils.getByteArray(fis);
        Headers headers = new Headers();
        headers.addHeader(Headers.CONTENT_ENCODING, Headers.DEFLATE);
        decoder.decode(byteArray, headers);
    }
}
