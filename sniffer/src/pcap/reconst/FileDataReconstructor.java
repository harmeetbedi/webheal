package pcap.reconst;

import java.io.File;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpDecodedOutput;
import pcap.reconst.output.HttpFlow;
import pcap.reconst.output.HttpRequestResponse;
import pcap.reconst.reconstructor.JpcapReconstructor;
import pcap.reconst.reconstructor.StreamReassembler;
import pcap.reconst.reconstructor.Reconstructor;
import pcap.reconst.reconstructor.TcpStream;

public class FileDataReconstructor {
    public Map<TcpConnection, TcpStream> reconstruct(File inputFile, Reconstructor reconstructor) throws Exception {
        return reconstructor.reconstruct(inputFile.getAbsolutePath());
    }

    public static void main(String[] args) {
        try {
            String filename = "dump.pcap";
            FileDataReconstructor fileDataReconstructor = new FileDataReconstructor();
            Set<Integer> set = new HashSet<Integer>();
            set.add(80);
            Map<TcpConnection, TcpStream> map = fileDataReconstructor.reconstruct(new File(filename), new JpcapReconstructor(new StreamReassembler(set,false),true));
            Map<TcpConnection, List<HttpRequestResponse>> httpPackets = HttpFlow.packetize(map, null, null, null,false);
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
