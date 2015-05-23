package pcap.reconst.beans;

import java.net.InetAddress;

public class TcpState {
    private InetAddress address;
    private long port;
    private long seq;
    private TcpFragment fragment;

    public TcpState(InetAddress address, long port) {
        this.address = address;
        this.port = port;
    }

    public InetAddress getAddress() {
        return address;
    }

    public long getPort() {
        return port;
    }

    public void setSeq(long seq) {
        this.seq = seq;
    }

    public void incrementSeq() {
        seq++;
    }

    public long getSeq() {
        return seq;
    }

    public void addToSeq(long length) {
        seq += length;
    }

    public TcpFragment getFragment() {
        return fragment;
    }

    public void setFragment(TcpFragment tcpFragment) {
        this.fragment = tcpFragment;
    }

    public String getOutputName() {
        return String.format("%s_%s", address.toString().replace("/", ""), port);
    }
}
