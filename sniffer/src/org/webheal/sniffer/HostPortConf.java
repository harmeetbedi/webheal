package org.webheal.sniffer;

import java.io.File;

import org.webheal.util.IExecutor;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpRequestResponse;

// configuration per host
public class HostPortConf
{
    private IHttpHandler impl;
    private long confReadLastModified;
    public final String host;
    public final int port;
    public final File conf;
    private final boolean verbose;
    HostPortConf(String host, int port, File conf,boolean verbose) {
        this.host = host;
        this.port = port;
        this.conf = conf;
        this.verbose = verbose;
    }
    // reload if there is config change 
    private void loadHandler(IExecutor<File, IHttpHandler> factory) throws Exception
    {
        long fileModified = conf.lastModified();
        if (impl == null || fileModified > confReadLastModified ) {
            impl = factory.execute(conf);
            confReadLastModified = fileModified;
        }
    }
    public void handleHttp(IExecutor<File, IHttpHandler> factory, TcpConnection conn, HttpRequestResponse http) throws Exception
    {
        boolean ignore = !( http.getHost().contains(host) && (conn.getDstPort() == port) );
        if ( verbose ) {
            System.out.println("handle > "+conn + (ignore?" (ignore) "+http.getHost()+":"+conn.getDstPort()+";"+host+":"+port:""));
        }
        if ( ignore ) {
            return;
        }
        loadHandler(factory);
        impl.handleHttp(conn, http);
    }
}
