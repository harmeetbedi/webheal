package org.webheal.sniffer;

import java.io.File;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
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
        Set<String> notExt = Utils.toSet("gif,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico", ",");
        Set<String> notContentType = Utils.toSet("image,xml", ",");
        File file = new File("/Users/harmeet/tmp/chrome/PCAP/CRS/4.pcap");
        Set<Integer> set = new HashSet<Integer>();
        set.add(80);
        PcapFileSniffer capture = new PcapFileSniffer(file,null,set,notExt,notContentType, null,handler,true);
        capture.init();
        capture.drainPackets();
    }
    public static void main(String[] args) throws Exception
    {
        if ( args.length == 0 ) {
            args = "-i en1 -m test.conf -v -t 30 -dh ./output/hits -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml".split(" ");
            args = "-f /Users/harmeet/tmp/test.pcap -t 30s -dh ./output/hits -dt /Users/harmeet/tmp/pcap/trace -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml -m test.conf".split(" ");
            args = "-f /Users/harmeet/tmp/test.pcap -m test.conf -dt /Users/harmeet/tmp/pcap/trace -ne gif,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,mov,ic -nt image,xml -dh ./output/hits".split(" ");
            //args = "-f dump.pcap -m test.conf -t 3 -dh ./output/hits -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml".split(" ");
            //args = "-f /Users/harmeet/tmp/out.pcap -m test.conf -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml -v -p 8080".split(" ");
            //args = "-f /Users/harmeet/tmp/test.pcap -C /Users/harmeet/tmp/pcap.props -ne gif,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,mov,ico -nt image,xml".split(" ");
//            args = "-i en1 -C /Users/harmeet/tmp/pcap.props -ne gif,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,mov,ico -nt image,xml -dh ./output/hits".split(" ");
//            args = "-i en1 -C /Users/harmeet/tmp/pcap.props -ne gif,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,mov,ico -nt image,xml -dh ./output/hits".split(" ");
//            args = "-i en0 -C /Users/harmeet/tmp/pcap.props -t 30 -ne gif,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,mov,ic -nt image,xml -dh ./output/hits -t 30s -dt /Users/harmeet/tmp/pcap/trace".split(" ");

        }
        // configuration file
        File logConfig = new File("./log4j.xml");
        DOMConfigurator.configure(logConfig.getAbsolutePath());

        Options payloadTestOptions = new Options();
        payloadTestOptions.addOption("f", true, "pcap file containing test payload");
        payloadTestOptions.addOption("m", true, "mod security rule file");
        payloadTestOptions.addOption("h", true, "(optional) comma separated list of hosts in http request that are tracked");
        payloadTestOptions.addOption("p", true, "(optional) http port that is tracked. default is 80");
        payloadTestOptions.addOption("C", true, "file with each line having format <comma separated hostnames>[:<port>]=<rule configuration file>. If this is specified, -m, -p and -h parmeters are ignored");
        payloadTestOptions.addOption("ne", true, "(optional) ignore requests for comma separated list of extensions");
        payloadTestOptions.addOption("nt", true, "(optional) ignore requests that result in comma separated list of content type response");
        payloadTestOptions.addOption("dh", true, "directory where rule hit logs are stored");
        payloadTestOptions.addOption("dt", true, "(optional) if present, directory where tcp flow files are stored. If not specified, tcp flows trace files are not created");
        payloadTestOptions.addOption("v", false, "(optional) if present, verbose output");

        Options options = new Options();
        options.addOption("i", true, "network interface");
        options.addOption("m", true, "mod security rule file");
        options.addOption("h", true, "(optional) comma separated list of hosts in http request that are tracked");
        options.addOption("p", true, "(optional) http port that is tracked. default is 80");
        options.addOption("C", true, "file with each line having format <hostname>[:<port>]=<rule configuration file>. If this is specified, -m, -p and -h parmeters are ignored");
        options.addOption("t", true, "max idle time for a network connection");
        //options.addOption("s", false, "(optional) ssl or not. default is not present");
        options.addOption("dh", true, "directory where rule hit logs are stored");
        options.addOption("ne", true, "(optional) ignore requests for comma separated list of extensions");
        options.addOption("nt", true, "(optional) ignore requests that result in comma separated list of content type response");
        options.addOption("dt", true, "(optional) if present, directory where tcp flow files are stored. If not specified, tcp flows trace files are not created");
        options.addOption("v", false, "(optional) if present, verbose output");
        final CommandLine cmd = getCmdLine(options, payloadTestOptions, args);
//        for ( Option opt : cmd.getOptions() ) {
//            System.out.println("opt : "+opt.getOpt()+" : "+opt.getValue());
//        }

        final boolean testMode;
        if ( cmd.hasOption('f') ) {
            testMode = true;
            if ( !(cmd.hasOption('m') || cmd.hasOption('C')) ) {
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
        Set<Integer> httpPortSet = new HashSet<Integer>();
        int httpPort = cmd.hasOption('p') ? Integer.parseInt(cmd.getOptionValue("p")) : 80;
        if ( !cmd.hasOption("C") ) {
            httpPortSet.add(httpPort);
        }

        System.out.println("libpath="+System.getProperty("java.library.path"));
        System.loadLibrary("jpcap");
        System.out.println("pcap successfully loaded");

        List<HostPortConf> confList = new ArrayList<HostPortConf>();
        HashSet<String> hostsFilter = new HashSet<String>();
        if ( cmd.hasOption('C') ) {
            Map<String,String> prop = Utils.readMap(cmd.getOptionValue("C"));
            for ( Map.Entry<String,String> entry : prop.entrySet() ) {
                String hostPort = entry.getKey();
                String confFile = entry.getValue();
            	String[] parts = hostPort.split(":");
            	File file = new File(confFile);
            	int port = 80;
            	if ( parts.length == 2) {
            		port = Integer.parseInt(parts[1].trim());
            	}
            	if ( parts.length < 1 || parts.length > 2 ) {
            		throw new Exception("Invalid host configuration : "+hostPort);
            	}
        		HostPortConf hpc = new HostPortConf(parts[0].trim(),port,file,verbose); 
                httpPortSet.add(port);
                hostsFilter.add(hpc.host);
                confList.add(hpc);
            }
        } else {
            File modSecConf = new File(cmd.getOptionValue("m"));
            fill(cmd,"h",hostsFilter);
            if( hostsFilter.size() == 0 ) {
            	confList.add(new HostPortConf("",httpPort,modSecConf,verbose));
            } else {
                for ( String host : hostsFilter ) {
                	confList.add(new HostPortConf(host,httpPort,modSecConf,verbose));
                }
            }
        }
        if ( verbose ) {
            for (HostPortConf conf : confList ) {
                System.out.println("conf: "+conf);
            }
        }
        File ruleHitDir = null;
        if ( cmd.hasOption("dh") ) {
            ruleHitDir = new File(cmd.getOptionValue("dh"));
            ruleHitDir.mkdirs();
        }
        IHttpHandler handler = IHttpHandler.Factory.autoReloadModSecurity(confList,ruleHitDir);
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
            PcapFileSniffer capture = new PcapFileSniffer(pcap,hostsFilter,httpPortSet,notExt,notContentType,tcpFlowDir,handler,verbose);
            capture.init();
            capture.drainPackets();
        } else {
            PassiveSniffer capture = new PassiveSniffer(interfaceName, Utils.getTime(maxIdle),hostsFilter,httpPortSet,notExt,notContentType,tcpFlowDir,handler,verbose);
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
}
