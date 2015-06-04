package org.webheal.sniffer;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.webheal.util.Utils;

public class Config
{
    public final boolean verbose;
    public final List<HostPortConf> hostPorts = new ArrayList<HostPortConf>();
    public final Set<Integer> portFilter = new HashSet<Integer>();
    public final Set<String> hostFilter = new HashSet<String>();
    public final File ruleHitDir;
    public final File confDir;
    public final File traceDir;
    public final Set<String> notExt;
    public final Set<String> notContentType;
    public final boolean pcapPktProcess;
    public final int pcapPktProcessCount;
    public final int pcapPktProcessTimeout;
    public final long streamTimeout;
    public final long streamProcessing;

    Config(String file) throws Exception {
        Map<String,String> map = Utils.readConfig(file);
        verbose = new Boolean(map.get("debug"));
        
        traceDir = getDir(map,"dir.trace");
        ruleHitDir = getDir(map,"dir.rule.hit");
        confDir = getDir(map,"dir.conf");

        // hosts
        String hosts = map.get("hosts");
        int defaultPort = new Integer(map.get("default.port"));
        Set<String> defaultHostnameFilter = Utils.toSet(map.get("default.filter.hostnames"), ",");
        hostFilter.addAll(defaultHostnameFilter);
        String defaultModSec = map.get("default.modsec.conf");
        if ( StringUtils.isEmpty(hosts)) {
            portFilter.add(defaultPort);
            hostPorts.add(new HostPortConf(defaultHostnameFilter,defaultPort,"",new File(defaultModSec),verbose));
        } else {
            String[] hostList = hosts.split(",");
            for ( String hostInp : hostList ) {
                String host = hostInp.trim().toLowerCase();
                int port = new Integer(map.get("host."+host+".port"));
                portFilter.add(port);
                String modSecConf = map.get("host."+host+".modsec.conf");
                String ruleHitFilePrefix = map.get("host."+host+".rulehitfile.prefix");
                Set<String> hostnameFilter = Utils.toSet(map.get("host."+host+".filter.hostnames"), ",");
                hostFilter.addAll(hostnameFilter);
                hostPorts.add(new HostPortConf(hostnameFilter,port,ruleHitFilePrefix,new File(confDir,modSecConf),verbose));
            }
        }
        
        notExt = Utils.toSet(map.get("ignore.request.ext"), ",");
        notContentType = Utils.toSet(map.get("ignore.response.contenttype"), ",");

        pcapPktProcess = new Boolean(map.get("pcap.iface.pktprocess"));
        pcapPktProcessCount = new Integer(map.get("pcap.iface.pktprocess.count"));
        pcapPktProcessTimeout = (int)Utils.getTime(map.get("pcap.iface.pktprocess.timeout")); 
        
        streamTimeout = Utils.getTime(map.get("net.stream.timeout"));
        streamProcessing = Utils.getTime(map.get("net.stream.processing")); 
    }
    private static File getDir(Map<String,String> map, String key) {
        String str = map.get(key);
        if ( StringUtils.isNotEmpty(str))  {
            File dir = new File(str);
            dir.mkdirs();
            return dir;
        } else {
            return null;
        }
    }
}
