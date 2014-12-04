package pcap.reconst.beans;

public class TcpFragment {
    public long seq = 0;
    public long len = 0;
    public long data_len = 0;
    public byte[] data = null;
    public TcpFragment next = null;
}
