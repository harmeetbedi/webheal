package org.webheal.sniffer;

import java.io.File;
import java.util.Set;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.xml.DOMConfigurator;

public class Main
{
    public static void main(String[] args) throws Exception
    {
        if ( args.length == 0 ) {
//            args = "-f /Users/harmeet/tmp/test.pcap -c webheal.properties".split(" ");
//            args = "-i en0 -c webheal.properties".split(" ");
        }
        // configuration file
        File logConfig = new File("./log4j.xml");
        DOMConfigurator.configure(logConfig.getAbsolutePath());

        Options options = new Options();
        options.addOption("f", true, "pcap file containing test payload. only one of -f or -i should be specified");
        options.addOption("i", true, "network interface. only one of -f or -i should be specified");
        options.addOption("c", true, "configuration file");
        CommandLine cmd = new PosixParser().parse( options, args,null,true);

        if ( !cmd.hasOption('c') || !(cmd.hasOption('i') || cmd.hasOption('f') ) ) {
            showHelp(options,options);
            return;
        }

        System.out.println("libpath="+System.getProperty("java.library.path"));
        System.loadLibrary("jpcap");
        System.out.println("pcap successfully loaded");

        Config conf = new Config(cmd.getOptionValue('c'));
        
        IHttpHandler handler = IHttpHandler.Factory.autoReloadModSecurity(conf.hostPorts,conf.ruleHitDir);
        boolean testMode = cmd.hasOption('f');
        File pcap = ( testMode ) ? new File(cmd.getOptionValue("f")) : null;
        String interfaceName = ( testMode ) ? null : cmd.getOptionValue("i");

        if ( testMode ) {
            PcapFileSniffer capture = new PcapFileSniffer(pcap,conf.hostFilter,conf.portFilter,conf.notExt,conf.notContentType,conf.traceDir,handler,conf.verbose);
            capture.init();
            capture.drainPackets();
        } else {
            PassiveSniffer capture = new PassiveSniffer(interfaceName, conf.streamTimeout,conf.hostFilter,conf.portFilter,conf.notExt,conf.notContentType,conf.traceDir,handler,conf.verbose);
            new Thread(capture,"sniffer").start();
            capture.init();
        }
    }
    
    private static void showHelp(Options options, Options payloadTestOptions) {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp( "java org.webheal.sniffer.Main", options );
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
