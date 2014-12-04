package pcap.reconst.compression;

import org.apache.log4j.Logger;

public class UncompressImpl implements Uncompress {
    private static Logger log = Logger.getLogger(UncompressImpl.class);

    private CompressionType compressionType;
    private byte[] input;
    private Dict dict;

    public UncompressImpl(CompressionType compressionType, byte[] input, Dict dict) {
        this.compressionType = compressionType;
        this.input = input;
        this.dict = dict;
    }

    public byte[] uncompress() {
        byte[] uncompressed = input;
        if (CompressionType.gzip == compressionType) {
            uncompressed = new Gunzip(input).unzip();
        } else if (CompressionType.deflate == compressionType) {
            uncompressed = new Inflate(input, dict).unzip();
        }
        return uncompressed;
    }
}