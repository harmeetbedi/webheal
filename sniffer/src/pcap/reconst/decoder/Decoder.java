package pcap.reconst.decoder;

import pcap.reconst.beans.DecodedData;
import pcap.reconst.beans.Headers;

public interface Decoder {
    public DecodedData decode(byte[] encodedStream, Headers headers);
}
