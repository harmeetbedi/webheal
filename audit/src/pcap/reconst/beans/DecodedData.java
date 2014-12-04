package pcap.reconst.beans;

public class DecodedData extends InputData {
    public DecodedData(byte[] data, Headers headers) {
        super(data, headers);
    }

    public DecodedData(InputData response) {
        super(response.getData(), response.getHeaders());
    }
}
