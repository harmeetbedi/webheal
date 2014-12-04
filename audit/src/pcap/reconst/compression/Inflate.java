package pcap.reconst.compression;

import org.apache.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.util.zip.Inflater;

public class Inflate implements Unzip {
    private static Logger log = Logger.getLogger(Inflate.class);

    private byte[] input;
    private Dict dict;

    public Inflate(byte[] input, Dict dict) {
        this.input = input;
        this.dict = dict;
    }

    public byte[] unzip() {
        Inflater inflater = new Inflater();

        byte[] output = new byte[100];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int compressedDataLength;
        inflater.setInput(input);
        try {
            compressedDataLength = inflater.inflate(output);
            if (compressedDataLength == 0 && inflater.needsDictionary()) {
                if (dict != null) {
                    inflater.setDictionary(dict.getDict());
                }
                while (true) {
                    compressedDataLength = inflater.inflate(output);
                    if (compressedDataLength == 0) {
                        break;
                    }
                    baos.write(output, 0, compressedDataLength);
                    if (compressedDataLength != output.length) {
                        break;
                    }
                }
            } else {
                baos.write(output, 0, compressedDataLength);
                while (true) {
                    compressedDataLength = inflater.inflate(output);
                    if (compressedDataLength == 0) {
                        break;
                    }
                    baos.write(output, 0, compressedDataLength);
                    if (compressedDataLength != output.length) {
                        break;
                    }
                }
            }
        } catch (Exception e) {
            log.debug(e, e);
            inflater.end();
        }
        inflater.end();
        return baos.toByteArray();
    }
}