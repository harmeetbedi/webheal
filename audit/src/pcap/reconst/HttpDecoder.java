package pcap.reconst;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import pcap.reconst.beans.DecodedData;
import pcap.reconst.beans.InputData;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.decoder.Decoder;
import pcap.reconst.decoder.DecoderFactory;
import pcap.reconst.output.HttpDecodedOutput;
import pcap.reconst.output.HttpRequestResponse;

public class HttpDecoder {
    private static Logger log = Logger.getLogger(HttpDecoder.class);

    private Map<TcpConnection, List<HttpRequestResponse>> httpPackets;
    private Decoder decoder = DecoderFactory.getDecoder();

    public HttpDecoder(Map<TcpConnection, List<HttpRequestResponse>> httpPackets) {
        this.httpPackets = httpPackets;
    }

    public Map<TcpConnection, List<HttpDecodedOutput>> decodeResponse() {
        Map<TcpConnection, List<HttpDecodedOutput>> decodedOutput = new HashMap<TcpConnection, List<HttpDecodedOutput>>();
        for (TcpConnection tcpConnection : httpPackets.keySet()) {
            List<HttpRequestResponse> httpOutput = httpPackets.get(tcpConnection);
            for ( HttpRequestResponse item : httpOutput) {
                HttpDecodedOutput output = decode(item);
                Utils.add(decodedOutput,tcpConnection, output);
            }
        }
        return decodedOutput;
    }

    private HttpDecodedOutput decode(HttpRequestResponse httpOutput) {
        HttpDecodedOutput httpDecodedOutput = new HttpDecodedOutput(httpOutput);
        InputData response = httpOutput.getResponse();
        DecodedData decodedResponse = new DecodedData(response);
        try {
            decodedResponse = decodeInput(response);
        } catch (Exception e) {
            e.printStackTrace();
        }
        httpDecodedOutput.setDecodedResponse(decodedResponse);
        log.debug(">>>>>>>>>>> decoded response");
        log.debug(decodedResponse.toString());
        return httpDecodedOutput;
    }

    private DecodedData decodeInput(InputData input) {
        DecodedData output = decoder.decode(input.getData(), input.getHeaders());
        log.debug(output);
        return output;
    }

}
