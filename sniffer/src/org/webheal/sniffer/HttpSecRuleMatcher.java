package org.webheal.sniffer;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.webheal.modsec.ModSecVariable;
import org.webheal.modsec.ModSecVariableMatcher;
import org.webheal.modsec.ModSecRuleParser.ModSecRule;

import pcap.reconst.beans.TcpConnection;
import pcap.reconst.output.HttpRequestResponse;

public class HttpSecRuleMatcher implements IHttpHandler
{
    private static final Logger STAT_LOG = Logger.getLogger("stat");
    private final ModSecRule rule;
    private static final IStat allStat = new Stat();
    private final IStat ruleStat;
    private final IStat stat;
    private File ruleHitDir;
    private final String ruleHitFilePrefix;
    public HttpSecRuleMatcher(ModSecRule rule, File ruleHitDir,String ruleHitFilePrefix) {
        this.rule = rule;
        this.ruleHitDir = ruleHitDir;
        this.ruleStat = new Stat();
        this.stat = new CatStat(ruleStat,allStat);
        this.ruleHitFilePrefix = ruleHitFilePrefix;
        //String str = rule.toString();
        //dump(0,rule);
        //System.out.println( rule );
    }
    @Override public void handleHttp(TcpConnection conn, HttpRequestResponse http) throws Exception
    {
        stat.incrCount();
        long startTime = System.currentTimeMillis();
        boolean failed = true;
        try {
            boolean match = isMatch(conn,http);
            failed = false;
            if ( match ) {
                stat.incrMatches();
                IHttpHandler.Factory.ruleMatched(ruleHitDir,rule,ruleHitFilePrefix).handleHttp(conn,http);
            }
        } finally {
            long tt = System.currentTimeMillis() - startTime;
            stat.addTime(tt);
            final Priority p;
            if ( failed ) {
                stat.incrErrors();
                p = Priority.ERROR;
            } else {
                p = Priority.DEBUG;
            }
            String msg = "rule:"+rule.id+", tt:"+tt+", stat["+ruleStat+"]"+", http["+http+"]" + ", allstat["+allStat+"]";
            STAT_LOG.log(p, msg);
        }
    }
    protected boolean isMatch(TcpConnection conn, HttpRequestResponse http) throws Exception
    {
        boolean match = isMatch(rule,conn,http);
        for ( ModSecRule child : rule.chain ) {
            if ( !match ) {
                break;
            }
            match = isMatch(child,conn,http);
        }
        return match;
    }
    protected boolean isMatch(ModSecRule msr, TcpConnection conn, HttpRequestResponse http) throws Exception
    {
        Map<HttpRequestResponse,Map<String,Object>> cache = new HashMap<HttpRequestResponse,Map<String,Object>>();
        //String[] varList = rule.variables.split("|");
        List<ModSecVariableMatcher> vars = ModSecVariableMatcher.parse(msr.variables);
        boolean match = false;
        // apply all the transforms 
        for ( ModSecVariableMatcher matcher : vars ) {
            if ( match ) {
                break;
            }
            Object value = ModSecVariable.getValue(http, matcher.var, cache);
            if ( value != null && value instanceof String ) {
                String str = (String)value;
                for ( String action : msr.transformActions ) {
                    str = matcher.normalize(str,action);
                }
                value = str;
            }
            match = matcher.match(value,msr.operator);
        }
        return match;
    }
    
    private static interface IStat {
        void incrCount();
        void incrErrors();
        void addTime(long time);
        void incrMatches();
    }
    private static class Stat implements IStat {
        private int count;
        private int errors;
        private long timeTaken;
        private int matches;
        public String toString() {
            return "matches:"+matches+", total:"+count+", err:"+errors+", tt:"+timeTaken;
        }
        @Override public void incrCount()
        {
            count++;
        }
        @Override public void incrErrors()
        {
            errors++;
        }
        @Override public void addTime(long time)
        {
            timeTaken += time;
        }
        @Override public void incrMatches()
        {
            matches++;
        }
    }
    private static class CatStat implements IStat {
        List<IStat> stats;
        public CatStat(IStat ... stats) {
            this.stats = Arrays.asList(stats);
        }
        @Override public void incrCount()
        {
            for ( IStat stat : stats ) {
                stat.incrCount();
            }
        }

        @Override public void incrErrors()
        {
            for ( IStat stat : stats ) {
                stat.incrErrors();
            }
        }

        @Override public void addTime(long time)
        {
            for ( IStat stat : stats ) {
                stat.addTime(time);
            }
        }

        @Override public void incrMatches()
        {
            for ( IStat stat : stats ) {
                stat.incrMatches();
            }
        }
    }
}
