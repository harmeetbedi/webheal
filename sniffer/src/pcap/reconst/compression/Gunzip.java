package pcap.reconst.compression;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.zip.GZIPInputStream;

public class Gunzip implements Unzip {
    private static Logger log = Logger.getLogger(Gunzip.class);

    private byte[] input;

    public Gunzip(byte[] input) {
        this.input = input;
//        try {
//            File file = new File("/Users/harmeet/tmp/sniffer/test-"+System.currentTimeMillis()+".gz");
//            System.out.println("FILE = "+file.getAbsolutePath());
//            FileUtils.writeByteArrayToFile(file, input);
//        } catch (IOException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
    }

    public byte[] unzip() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        GZIPInputStream gzipis = null;
        ByteArrayInputStream bais = null;

        try {
            byte[] buf = new byte[100];
            bais = new ByteArrayInputStream(input);
            gzipis = new GZIPInputStream(bais);
            int size;
            while ((size = gzipis.read(buf)) != -1) {
                baos.write(buf, 0, size);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            log.debug(ex, ex);
        } finally {
            if (bais != null) {
                try {
                    bais.close();
                } catch (IOException e) {
                    log.debug(e, e);
                }
            }
            if (gzipis != null) {
                try {
                    gzipis.close();
                } catch (IOException e) {
                    log.debug(e, e);
                }
            }
            try {
                baos.close();
            } catch (IOException e) {
                log.debug(e, e);
            }
        }

        byte[] bytesToReturn = baos.toByteArray();
        if (bytesToReturn.length == 0) {
            return input;
        } else {
            return bytesToReturn;
        }
    }
}