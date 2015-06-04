package org.webheal.sniffer;

import java.io.File;
import java.util.Set;

import org.webheal.util.IExecutor;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpRequestResponse;

// configuration per host
public class HostPortConf
{
    private IHttpHandler impl;
    private long confReadLastModified;
    public final int port;
    public final File conf;
    public final String ruleHitFilePrefix;
    private final boolean verbose;
    private Set<String> hostFilter;
    HostPortConf(Set<String> hostFilter, int port, String ruleHitFilePrefix, File conf,boolean verbose) {
        this.hostFilter = hostFilter;
        this.port = port;
        this.conf = conf;
        this.verbose = verbose;
        this.ruleHitFilePrefix = ruleHitFilePrefix;
    }
    public String toString() {
        return String.format("%s:%d - %s", String.valueOf(hostFilter), port, conf.getAbsoluteFile());
    }
    // reload if there is config change 
    private void loadHandler(IExecutor<HostPortConf, IHttpHandler> factory) throws Exception
    {
        long fileModified = conf.lastModified();
        if (impl == null || fileModified > confReadLastModified ) {
            impl = factory.execute(this);
            confReadLastModified = fileModified;
        }
    }
    public void handleHttp(IExecutor<HostPortConf, IHttpHandler> factory, TcpConnection conn, HttpRequestResponse http) throws Exception
    {
        boolean ignore = ( conn.getDstPort() != port);
        if ( !ignore && hostFilter.size() > 0 ) {
            ignore = true;
            String reqHost = http.getHost();
            for ( String host : hostFilter ) { 
                if ( reqHost.contains(host) ) {
                    ignore = false;
                    break;
                }
            }
        }
        if ( verbose ) {
            System.out.println("handle > "+conn + (ignore?" (ignore) "+http.getHost()+":"+conn.getDstPort()+";"+hostFilter+":"+port:""));
        }
        if ( ignore ) {
            return;
        }
        loadHandler(factory);
        impl.handleHttp(conn, http);
    }
}
