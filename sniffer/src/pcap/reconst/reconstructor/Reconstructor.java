package pcap.reconst.reconstructor;

import pcap.reconst.beans.TcpConnection;

import java.util.Map;

public interface Reconstructor {
    Map<TcpConnection, TcpStream> reconstruct(String filename) throws Exception;
}