package org.webheal.sniffer;

import java.io.File;
import java.io.StringReader;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.xml.DOMConfigurator;
import org.webheal.modsec.ModSecRuleParser;
import org.webheal.modsec.ModSecRuleParser.ModSecRule;
import org.webheal.util.Utils;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpRequestResponse;

public class Cli
{
    public static void main1(String[] args) throws Exception {
        System.out.println("libpath="+System.getProperty("java.library.path"));
        System.loadLibrary("jpcap");
        System.out.println("pcap successfully loaded");
        
        final String ruleTxt = "SecRule REQUEST_URI \"/$\" \"phase:4,deny,chain,log,msg:'Directory index returned',id:54631\"";
        ModSecRule rule = ModSecRuleParser.getRule(ruleTxt);
        IHttpHandler handler = new HttpSecRuleMatcher(rule, null) {
            @Override public void handleHttp(TcpConnection conn, HttpRequestResponse http) throws Exception
            {
                boolean match = isMatch(conn,http);
                System.out.println("MATCH : "+match);
                System.out.println("conn:"+conn+", host="+http.getHost()+", uri= "+http.getRequestUri());
                List<String> lines = IOUtils.readLines(new StringReader(ruleTxt));
                for ( String line : lines ) {
                    System.out.println(line);
                }
            }
        };

        // -nt image,xml
        Set<String> notExt = Utils.toSet("gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico", ",");
        Set<String> notContentType = Utils.toSet("image,xml", ",");
        File file = new File("/Users/harmeet/tmp/chrome/PCAP/CRS/4.pcap");
        PcapFileSniffer capture = new PcapFileSniffer(file,null,notExt,notContentType, null,handler,true);
        capture.init();
        capture.drainPackets();
    }
    public static void main(String[] args) throws Exception
    {
        if ( args.length == 0 ) {
            //args = "-i en0 -m test.conf -t 30 -dh ./output/hits -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml".split(" ");
            //args = "-f dump.pcap -m test.conf -t 3 -dh ./output/hits -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml".split(" ");
            //args = "-f ./pcap/CRS/100.pcapng -m rules.conf -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml".split(" ");
        }
        // configuration file
        File logConfig = new File("./log4j.xml");
        DOMConfigurator.configure(logConfig.getAbsolutePath());

        Options payloadTestOptions = new Options();
        payloadTestOptions.addOption("f", true, "pcap file containing test payload");
        payloadTestOptions.addOption("m", true, "mod security rule file");
        payloadTestOptions.addOption("h", true, "(optional) comma separated list of hosts in http request that are tracked");
        payloadTestOptions.addOption("C", true, "file with each line having format <comma separated hostnames>=<rule configuration file>. If this is specified, -m and -h parmeters are ignored");
        payloadTestOptions.addOption("ne", true, "(optional) ignore requests for comma separated list of extensions");
        payloadTestOptions.addOption("nt", true, "(optional) ignore requests that result in comma separated list of content type response");
        payloadTestOptions.addOption("dt", true, "(optional) if present, directory where tcp flow files are stored. If not specified, tcp flows trace files are not created");

        Options options = new Options();
        options.addOption("i", true, "network interface");
        options.addOption("m", true, "mod security rule file");
        options.addOption("h", true, "(optional) comma separated list of hosts in http request that are tracked");
        options.addOption("C", true, "file with each line having format <comma separated hostnames>=<rule configuration file>. If this is specified, -m and -h parmeters are ignored");
        options.addOption("t", true, "max idle time for a network connection");
        //options.addOption("s", false, "(optional) ssl or not. default is not present");
        options.addOption("dh", true, "directory where rule hit logs are stored");
        options.addOption("ne", true, "(optional) ignore requests for comma separated list of extensions");
        options.addOption("nt", true, "(optional) ignore requests that result in comma separated list of content type response");
        options.addOption("dt", true, "(optional) if present, directory where tcp flow files are stored. If not specified, tcp flows trace files are not created");
        options.addOption("v", false, "(optional) if present, verbose output");
        CommandLine cmd = getCmdLine(options, payloadTestOptions, args);

        final boolean testMode;
        if ( cmd.hasOption('f') ) {
            testMode = true;
            if ( !cmd.hasOption('m') ) {
                showHelp(options,payloadTestOptions);
                return;
            }
        } else {
            testMode = false;
            if ( !cmd.hasOption('i') || !cmd.hasOption('t') || !(cmd.hasOption('m') || cmd.hasOption('C')) ) { 
                showHelp(options,payloadTestOptions);
                return;
            }
        }
        final boolean verbose = cmd.hasOption('v'); 

        System.out.println("libpath="+System.getProperty("java.library.path"));
        System.loadLibrary("jpcap");
        System.out.println("pcap successfully loaded");

        File ruleHitDir = null;
        if ( cmd.hasOption("dh") ) {
            ruleHitDir = new File(cmd.getOptionValue("dh"));
            ruleHitDir.mkdirs();
        }
        Map<String,File> hostToConfMap = new LinkedHashMap<String,File>();
        HashSet<String> hostsFilter = new HashSet<String>();
        if ( cmd.hasOption('C') ) {
            Properties prop = Utils.readProperties(cmd.getOptionValue("C"));
            Enumeration<?> names = prop.propertyNames();
            while ( names.hasMoreElements() ) {
                String hosts = (String)names.nextElement();
                String confFile = prop.getProperty(hosts);
                for ( String host : getHosts(hosts) ) {
                    hostToConfMap.put(host,new File(confFile));
                    hostsFilter.add(host);
                }
            }
        } else {
            File modSecConf = new File(cmd.getOptionValue("m"));
            fill(cmd,"h",hostsFilter);
            if( hostsFilter.size() == 0 ) {
                hostToConfMap.put("",modSecConf);
            } else {
                for ( String host : hostsFilter ) {
                    hostToConfMap.put(host,modSecConf);
                }
            }
        }
        IHttpHandler handler = IHttpHandler.Factory.autoReloadModSecurity(hostToConfMap,ruleHitDir);
        File pcap = ( testMode ) ? new File(cmd.getOptionValue("f")) : null;
        String interfaceName = ( testMode ) ? null : cmd.getOptionValue("i");
        String maxIdle = ( testMode ) ? null : cmd.getOptionValue("t");
        Set<String> notExt = new HashSet<String>();
        Set<String> notContentType = new HashSet<String>();
        File tcpFlowDir = null; 
        fill(cmd,"ne",notExt);
        fill(cmd,"nt",notContentType);
        if ( cmd.hasOption("dt") ) {
            tcpFlowDir = new File(cmd.getOptionValue("dt"));
            tcpFlowDir.mkdirs();
        }
        //IHttpHandler handler = IHttpHandler.Factory.trace();
        if ( testMode ) {
            PcapFileSniffer capture = new PcapFileSniffer(pcap,hostsFilter,notExt,notContentType,tcpFlowDir,handler,verbose);
            capture.init();
            capture.drainPackets();
        } else {
            PassiveSniffer capture = new PassiveSniffer(interfaceName, Utils.getTime(maxIdle),hostsFilter,notExt,notContentType,tcpFlowDir,handler,verbose);
            new Thread(capture,"sniffer").start();
            capture.init();
        }
    }
    
    private static void showHelp(Options options, Options payloadTestOptions) {
        System.out.println("TO RUN PASSIVE SNIFFER:");
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "java org.webheal.sniffer.Cli", options );
        System.out.println("");
        System.out.println("TO RUN TEST PAYLOAD:");
        formatter = new HelpFormatter();
        formatter.printHelp( "java org.webheal.sniffer.Cli", payloadTestOptions );
    }
    private static CommandLine getCmdLine(Options options, Options payloadTestOptions, String[] args) throws Exception {
        CommandLine cmd = new PosixParser().parse( options, args,null,true);
        CommandLine payloadTestCmd = new PosixParser().parse( payloadTestOptions, args,null,true);
        if ( payloadTestCmd.hasOption('f') ) {
            return payloadTestCmd;
        } else {
            return cmd;
        }
    }
    private static void fill(CommandLine cmd, String option,Set<String> set) {
        String value = cmd.getOptionValue(option);
        if ( StringUtils.isEmpty(value)) {
            return;
        }
        String[] parts = StringUtils.split(value, ",");
        for ( String part : parts ) {
            String ext = part.trim();
            if ( StringUtils.isNotEmpty(ext)) {
                set.add(ext.toLowerCase());
            }
        }
    }
    private static Set<String> getHosts(String value) {
        Set<String> set = new LinkedHashSet<String>();
        String[] parts = StringUtils.split(value, ",");
        for ( String part : parts ) {
            String ext = part.trim();
            if ( StringUtils.isNotEmpty(ext)) {
                set.add(ext.toLowerCase());
            }
        }
        return set;
    }
}
