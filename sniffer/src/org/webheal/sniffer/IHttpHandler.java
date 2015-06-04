package org.webheal.sniffer;

import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.webheal.modsec.ModSecRuleParser;
import org.webheal.modsec.ModSecRuleParser.ModSecRule;
import org.webheal.util.IExecutor;
import org.webheal.util.Utils;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpRequestResponse;
import au.com.bytecode.opencsv.CSVWriter;

public interface IHttpHandler
{
    public void handleHttp(TcpConnection conn, HttpRequestResponse http) throws Exception;
    
    public static class Factory {
        public static IHttpHandler cat(final List<IHttpHandler> handlers) throws Exception
        {
            IHttpHandler result = new IHttpHandler() {
                @Override public void handleHttp(TcpConnection conn, HttpRequestResponse http) throws Exception
                {
                    for ( IHttpHandler handler : handlers ) {
                        handler.handleHttp(conn, http);
                    }
                }
            };
            return result;
        }
        public static IHttpHandler autoReloadModSecurity(final List<HostPortConf> confList, final File ruleHitDir) throws Exception
        {
            IExecutor<HostPortConf, IHttpHandler> factory = new IExecutor<HostPortConf, IHttpHandler>() {
                @Override public IHttpHandler execute(HostPortConf param) throws Exception
                {
                    return modSecurity(param.conf,ruleHitDir,param.ruleHitFilePrefix);
                } 
                
            };
            return new AutoReloadHttpHandler(confList,factory);
        }
        public static IHttpHandler modSecurity(final File conf, File ruleHitDir,String ruleHitFilePrefix) throws Exception
        {
            List<ModSecRule> rules = ModSecRuleParser.getRules(conf);
            List<IHttpHandler> matchers = new ArrayList<IHttpHandler>();
            for( ModSecRule rule: rules ){
                if ( StringUtils.isEmpty(rule.id) ) {
                    continue;
                }
                matchers.add(new HttpSecRuleMatcher(rule,ruleHitDir,ruleHitFilePrefix));
                //break;
            }
            IHttpHandler result = IHttpHandler.Factory.cat(matchers);
            result = cat(new Trace(),result);
            return result;
        }

        public static IHttpHandler cat(final IHttpHandler ... handlers) throws Exception
        {
            return cat(Arrays.asList(handlers));
        }
        public static IHttpHandler trace() {
            return new Trace();
        }

        public static class Trace implements IHttpHandler {
            Trace() { }
            @Override public void handleHttp(TcpConnection conn, HttpRequestResponse http) throws Exception
            {
                String msg = http.toString();
                System.out.println(msg);
            }
        }
        public static IHttpHandler ruleMatched(File ruleHitDir,ModSecRule rule, String ruleHitFilePrefix)
        {
            return new RuleHit(ruleHitDir,rule,ruleHitFilePrefix);
        }
        private static class RuleHit implements IHttpHandler {
            private final ModSecRule rule;
            private final File ruleHitDir;
            private final String ruleHitFilePrefix;
            private static final DateFormat DF = new SimpleDateFormat("yyMMdd-HHmm");
            private RuleHit(File ruleHitDir, ModSecRule rule, String ruleHitFilePrefix) { this.ruleHitDir = ruleHitDir; this.rule = rule; this.ruleHitFilePrefix = ruleHitFilePrefix; }
            @Override public void handleHttp(TcpConnection conn, HttpRequestResponse http) throws Exception
            {
                HitRow hr = new HitRow(rule,conn,http);
                if ( ruleHitDir != null ) {
                    String name = "rh-"+hr.date+".txt";
                    if ( StringUtils.isNotEmpty(ruleHitFilePrefix) ) {
                        name = ruleHitFilePrefix+"."+name;
                    }
                    File file = new File(ruleHitDir,name);
                    Utils.appendQuietly(file,hr.toString());
                } else {
                    System.out.println(hr);
                }
            }
            
            private static class HitRow {
                private long time;
                private String ruleId;
                private String conn;
                private String host;
                private String uri;
                private String date;

                HitRow(ModSecRule rule, TcpConnection conn, HttpRequestResponse http) {
                    this.time = System.currentTimeMillis();
                    this.ruleId = rule.id;
                    this.conn = conn.toString();
                    this.host = http.getHost();
                    this.uri = http.getRequestUri();
                    this.date = DF.format(new Date(time));
                }
                public String toString() {
                    StringWriter str = new StringWriter();
                    CSVWriter cwriter = new CSVWriter(str);
                    cwriter.writeNext(new String[] { time+"",date,ruleId, conn, host, uri });
                    try {
                        cwriter.flush();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    return str.toString().trim();
                }
            }
        }
    }

}
