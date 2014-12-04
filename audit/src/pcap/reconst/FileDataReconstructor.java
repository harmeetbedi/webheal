package pcap.reconst;

import pcap.reconst.output.Http;
import pcap.reconst.output.HttpDecodedOutput;
import pcap.reconst.output.HttpRequestResponse;
import pcap.reconst.reconstructor.JpcapReconstructor;
import pcap.reconst.beans.TcpConnection;
import pcap.reconst.reconstructor.PacketReassembler;
import pcap.reconst.reconstructor.Reconstructor;
import pcap.reconst.reconstructor.TcpReassembler;

import java.io.File;
import java.util.List;
import java.util.Map;

public class FileDataReconstructor {
    public Map<TcpConnection, TcpReassembler> reconstruct(File inputFile, Reconstructor reconstructor) throws Exception {
        return reconstructor.reconstruct(inputFile.getAbsolutePath());
    }

    public static void main(String[] args) {
        try {
            String filename = "dump.pcap";
            FileDataReconstructor fileDataReconstructor = new FileDataReconstructor();
            Map<TcpConnection, TcpReassembler> map = fileDataReconstructor.reconstruct(new File(filename), new JpcapReconstructor(new PacketReassembler(),true));
            Http http = new Http(map);
            Map<TcpConnection, List<HttpRequestResponse>> httpPackets = http.packetize();
            System.out.println("number of packets " + httpPackets.size());
            for (TcpConnection tcpConnection : httpPackets.keySet()) {
                System.out.println(tcpConnection);
                List<HttpRequestResponse> httpOutput = httpPackets.get(tcpConnection);
//                System.out.println(new String(httpOutput.getRequest().getData()));
//                System.out.println(new String(httpOutput.getResponse().getData()));
            }
            HttpDecoder httpDecoder = new HttpDecoder(httpPackets);
            Map<TcpConnection, List<HttpDecodedOutput>> decodedPackets = httpDecoder.decodeResponse();
            for (TcpConnection tcpConnection : decodedPackets.keySet()) {
                System.out.println(tcpConnection);
                List<HttpDecodedOutput> httpDecodedOutput = decodedPackets.get(tcpConnection);
//                System.out.println(new String(httpDecodedOutput.getDecodedResponse().getData()));
            }

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }
}
