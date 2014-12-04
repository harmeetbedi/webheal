package pcap.reconst.compression;

import org.apache.log4j.Logger;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPOutputStream;

public class GZip implements Zip {
    private static Logger log = Logger.getLogger(GZip.class);

    private byte[] input;

    public GZip(byte[] input) {
        this.input = input;
    }

    public byte[] zip() {
        byte[] zipped = new byte[0];
        ByteArrayOutputStream baos = null;
        BufferedOutputStream bos = null;
        try {
            baos = new ByteArrayOutputStream();
            bos = new BufferedOutputStream(new GZIPOutputStream(baos));
            bos.write(input);
            zipped = baos.toByteArray();
            //bos.close();
            //baos.close();
        } catch (IOException ioe) {
            log.debug(ioe, ioe);
        } finally {
            if (baos != null) {
                try {
                    baos.close();
                } catch (IOException e) {
                    log.debug(e, e);
                }
            }
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e) {
                    log.debug(e, e);
                }
            }
        }
        return zipped;
    }
}
