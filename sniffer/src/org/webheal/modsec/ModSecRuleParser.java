package org.webheal.modsec;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

public class ModSecRuleParser
{
    public static List<ModSecRule> getRules(File file) throws IOException {
        return getRules(file,true);
    }
    public static ModSecRule getRule(String txt) throws IOException {
        List<String> lines = IOUtils.readLines(new StringReader(txt));
        List<ModSecRule> rules = getRules(lines);
        if ( rules.size() > 0 ) {
            return rules.get(0);
        } else {
            return null;
        }
    }
    public static List<ModSecRule> getRules(String txt) throws IOException {
        List<String> lines = IOUtils.readLines(new StringReader(txt));
        return getRules(lines);
    }
    public static List<ModSecRule> getRules(List<String> lines) throws IOException {
        return getRules(lines,true);
    }
    private static List<ModSecRule> getRules(File file,boolean chain) throws IOException {
        List<String> lines = FileUtils.readLines(file);
        return getRules(lines,chain);
    }
    private static List<ModSecRule> getRules(List<String> lines,boolean chain) throws IOException {
        if ( chain ) {
            List<ModSecRule> rules = getRules(lines,false);
            List<ModSecRule> result = new ArrayList<ModSecRule>();
            ModSecRule prev = null;
            boolean prevChained = false;
            for ( ModSecRule rule : rules ) {
                if ( prevChained ) {
                    prev.chain.add(rule);
                    prevChained = rule.chained;
                    // note: top rule is maintained as previous rule, but chaining continuation is determined from existing rule
                    continue;
                }
                prev = rule;
                prevChained = rule.chained;
                result.add(rule);
            }
            return result;
        }
        List<ModSecRule> result = new ArrayList<ModSecRule>();
        String prev = null;
        int idx = 0;
        for ( String src : lines ) {
            idx++;
            String line = src.trim();
            if ( StringUtils.isEmpty(line)) {
                continue;
            }
            //System.out.println(idx+" : "+line);
            if ( line.endsWith("\\")) {
                line = line.substring(0,line.length()-1).trim();
                if ( prev == null ) {
                    prev = line;
                } else {
                    prev = prev + " "+line;
                }
                continue;
            }
            if ( prev != null ) {
                line = prev + " "+line;
                prev = null;
            }
            if ( !line.startsWith("SecRule ")) {
                continue;
            }
            // now we have a complete sec rule line
            List<String> tok = getRuleTokens(line);
            if ( tok.size() == 2 || tok.size() == 3 ) {  
                result.add(new ModSecRule(tok));
            } else {
                System.out.println("INVALID_RULE : "+line);
            }
        }
        return result;
    }
    
    public static void main(String[] args) throws IOException
    {
        File file = new File("./test.conf");
        List<ModSecRule> list = getRules(file);
        int idx = 0;
        for (ModSecRule rule : list) {
            idx++;
            System.out.println(idx + ": " + rule);
        }
    }
    
    private static List<String> getRuleTokens(String line) {
        List<String> result = new ArrayList<String>();
        List<String> tok = ModSecUtils.tokenizeRuleParts(line, ' ');
        for ( int i = 1 ; i < tok.size() ; i++ ) {
            String txt = tok.get(i).trim();
            if ( StringUtils.isNotEmpty(txt)) {
                result.add(txt);
            }
        }
        return result;
    }

    public static class ModSecRule {
        public final String variables;
        public final String operator;
        public final String id;
        public final Set<String> transformActions = new LinkedHashSet<String>();
        public final boolean chained;
        public final ArrayList<ModSecRule> chain = new ArrayList<ModSecRule>();

        // SecRule VARIABLES OPERATOR [ACTIONS]
        ModSecRule(List<String> tok) {
            String id = null;
            boolean chained = false;
            variables = tok.get(0);
            operator = tok.get(1);
            if ( tok.size() > 2 ) {
                String actions = tok.get(2);
                if ( actions.startsWith("\"")) {
                    actions = actions.substring(1);
                }
                if ( actions.endsWith("\"")) {
                    actions = actions.substring(0,actions.length()-1);
                }
                List<String> actList = ModSecUtils.tokenizeRuleParts(actions, ',');
                for ( String item : actList ) {
                    String src = item.replaceAll("'", "").trim();

                    if (src.indexOf(":") > 0) {
                        String[] parts = src.split(":", 2);
                        String name = parts[0];
                        String value = parts[1];
                        if ( name.equals("id") ) {
                            id = value;
                        }
                        if ( name.equals("t")) {
                            if ( value.equals("none")) {
                                transformActions.clear();
                            } else {
                                transformActions.add(value);
                            }
                        }
                    } else {
                        if ( src.equals("chain")) {
                            chained = true;
                        }
                    }
                }
            }
            this.chained = chained;
            this.id = id;
        }
        
        public String toString() {
            StringBuffer buf = new StringBuffer();
            if ( id != null ) {
                buf.append("id:"+id);
                buf.append(" ");
            }
            buf.append("v:"+variables);
            buf.append(" ");
            buf.append("op:"+operator);
            buf.append(" ");
            buf.append("t:"+transformActions);
            if ( chained ) {
                buf.append(" ");
                buf.append("chain:"+chain.size());
                for ( ModSecRule item : chain ) {
                    buf.append("\r\n    "+item);
                }
            }
            String str = buf.toString();
            return str;
        }
    }
}
