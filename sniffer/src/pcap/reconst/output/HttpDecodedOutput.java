package pcap.reconst.output;

import pcap.reconst.beans.DecodedData;

public class HttpDecodedOutput extends HttpRequestResponse {
    private DecodedData decodedResponse;

    public HttpDecodedOutput(HttpRequestResponse httpOutput) {
        super(httpOutput.conn,httpOutput.getRequestUri(),httpOutput.getRequestUri().getBytes(), httpOutput.getPayload(), httpOutput.getRequest(), httpOutput.getResponse());
    }

    public DecodedData getDecodedResponse() {
        return decodedResponse;
    }

    public void setDecodedResponse(DecodedData decodedResponse) {
        this.decodedResponse = decodedResponse;
    }
}