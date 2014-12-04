package org.webheal.sniffer;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

import org.webheal.util.IExecutor;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpRequestResponse;

/** reloads http handler if file changes */ 
public class AutoReloadHttpHandler implements IHttpHandler
{
    private static class HostConf {
        private IHttpHandler impl;
        private final File file;
        private long lastModified;
        HostConf(File file) {
            this.file = file;
        }
    }
    private final IExecutor<File, IHttpHandler> factory;
    private final Map<String,HostConf> hostToConfMap = new LinkedHashMap<String,HostConf>();

    public AutoReloadHttpHandler(final Map<String,File> src,IExecutor<File,IHttpHandler> factory) {
        this.factory = factory;
        for ( Map.Entry<String,File> entry : src.entrySet() ) {
            hostToConfMap.put(entry.getKey(),new HostConf(entry.getValue()));
        }
    }
    public void handleHttp(TcpConnection conn, HttpRequestResponse http) throws Exception {
        for ( Map.Entry<String,HostConf> entry : hostToConfMap.entrySet() ) {
            String entryHost = entry.getKey();
            boolean hostMatch = http.getHost().contains(entry.getKey()); 
            if ( !hostMatch ) {
                continue;
            }
            HostConf conf = entry.getValue();
            long fileModified = conf.file.lastModified();
            if ( conf.impl == null ) {
                conf.impl = factory.execute(conf.file);
                conf.lastModified = fileModified;
            }
            else if ( fileModified > conf.lastModified ) {
                conf.impl = factory.execute(conf.file);
                conf.lastModified = fileModified;
            }
            conf.impl.handleHttp(conn, http);
        }
    }
}
