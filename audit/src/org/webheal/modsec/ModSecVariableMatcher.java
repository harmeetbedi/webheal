package org.webheal.modsec;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

public class ModSecVariableMatcher
{

    private static final Logger LOG = Logger.getLogger(ModSecVariable.class);

    private final String qualifier;
    private final boolean not;
    public final ModSecVariable var;

    ModSecVariableMatcher(ModSecVariable var, boolean not, String qualifier) {
        this.var = var;
        this.not = not;
        this.qualifier = qualifier;
    }

    public final String normalize(String value,String function)
    {
        ModSecAction action = ModSecAction.getInstance(function);
        if ( action == null ) {
            LOG.warn("normalization not implemented for : "+function);
            return value;
        } else { 
            try  {
                value = action.normalize(value);
            } catch(Throwable t) {
                LOG.error("normalization failed : "+t.toString());
            }
        }
        return value;
    }
    
    //public abstract String getValue(HttpRequestResponse http);

    public boolean match(Object value,String pattern)
    {
        if ( pattern.startsWith("\"")) {
            pattern = pattern.substring(1);
        }
        if ( pattern.endsWith("\"") ) {
            pattern = pattern.substring(0,pattern.length()-1);
        }
        if ( value instanceof Map && !StringUtils.isEmpty(qualifier) ) {
            if ( qualifier.startsWith("/") && qualifier.endsWith("/")) {
                String regex = qualifier.substring(1,qualifier.length()-2);
                Map<String,String> qualValueMap = new LinkedHashMap<String,String>();
                for ( Map.Entry<String, String> entry : ((Map<String,String>)value).entrySet() ) {
                    String key = entry.getKey();
                    if ( key.matches(regex) ) {
                        qualValueMap.put(key, entry.getValue());
                    }
                }
                value = qualValueMap;
            } else {
                Map<String,String> map = (Map<String,String>)value;
                //String keys = map.keySet();
                String str = map.get(qualifier);
                value = str;
            }
        }
        if ( !pattern.startsWith("@") ) {
            pattern = "@rx "+pattern;
        }
        int idx = pattern.indexOf(' ');
        final ModSecOperator op;
        if ( idx >= 0 ) {
            String type = pattern.substring(0,idx);
            op = ModSecOperator.getInstance(type);
            pattern = pattern.substring(idx+1);
        } else {
            op = ModSecOperator.getInstance(pattern);
            pattern = "";
        }
        return match(value, op, pattern);
    }
    private boolean match(Object value, ModSecOperator op, String pattern) {
        try {
            boolean match = false;
            if ( value instanceof Map ) {
                for ( String strValue : ((Map<String,String>)value).values() ) {
                    match = op.match(value,pattern);
                    if ( match ) {
                        break;
                    }
                }
            } else if ( value instanceof String ) {
                match = op.match(value,pattern);
            }
            if ( not ) {
                match = !match;
            }
            return match;
        } catch (Throwable e) {
            LOG.error("failed to match : "+pattern, e);
            return false;
        }
    }


    public static List<ModSecVariableMatcher> parse(String variables)
    {
        if ( variables.startsWith("\"") ) {
            variables = variables.substring(1); 
        }
        if ( variables.endsWith("\"") ) {
            variables = variables.substring(0,variables.length() - 1); 
        }
        List<ModSecVariableMatcher> list = new ArrayList<ModSecVariableMatcher>();
        String[] specs = StringUtils.split(variables,"|");
        for (String spec : specs) {
            String[] parts = StringUtils.split(spec,":");
            String name = parts[0];
            String qualifier = null;
            boolean not = false;
            if ( parts.length > 1) {
                qualifier = parts[1];
            }
            if ( name.startsWith("!")) {
                not = true;
                name = name.substring(1);
            }
            ModSecVariable<?> var = ModSecVariable.newInstance(name);
            if ( var != null ) {
                ModSecVariableMatcher matcher = new ModSecVariableMatcher(var,not,qualifier);
                list.add(matcher);
            }
        }
        return list;
    }
}