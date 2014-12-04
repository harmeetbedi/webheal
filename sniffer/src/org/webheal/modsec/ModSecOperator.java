package org.webheal.modsec;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

enum ModSecOperator
{
    //  Returns true if the parameter string is found anywhere in the input
    contains {
        @Override protected boolean strMatch(String src, String pattern) throws Exception
        {
            return src.contains(pattern);
        }
    },
    // Performs a case-insensitive match of the provided phrases against the desired input value.
    pm {
        @Override protected boolean strMatch(String src, String pattern) throws Exception
        {
            String[] parts = StringUtils.split(pattern," ");
            for ( String part : parts ) {
                if ( src.contains(part) ) {
                    return true;
                }
            }
            return false;
        }
    },
    rx {
        @Override protected boolean strMatch(String src, String pattern) throws Exception
        {
            return src.matches(".*"+pattern+".*");
        }
    },
    startsWith {
        @Override protected boolean strMatch(String src, String pattern) throws Exception
        {
            return src.startsWith(pattern);
        }
    },
    endsWith {
        @Override protected boolean strMatch(String src, String pattern) throws Exception
        {
            return src.endsWith(pattern);
        }
    };
    public boolean match(Object src, String pattern) throws Exception {
        if ( src == null ) {
            return false;
        }
        else if ( src instanceof String ) {
            return strMatch((String)src,pattern);
        }
        else if ( src instanceof Integer ) {
            return intMatch((Integer)src,pattern);
        }
        else if ( src instanceof Map ) {
            return mapMatch((Map<String,String>)src,pattern);
        }
        else if ( src instanceof Set ) {
            return setMatch((Set<String>)src,pattern);
        } else {
            LOG.warn("Invalid src input type : "+src.getClass().getName());
            return false;
        }
    }

    protected boolean strMatch(String src, String pattern) throws Exception {
        return false;
    }
    protected boolean intMatch(int src, String pattern) throws Exception {
        return false;
    }
    protected boolean mapMatch(Map<String,String> src, String pattern) throws Exception {
        return false;
    }
    protected boolean setMatch(Set<String> src, String pattern) throws Exception {
        return false;
    }

    private static final Logger LOG = Logger.getLogger(ModSecAction.class);
    private static Map<String, ModSecOperator> s_map = new HashMap<String, ModSecOperator>();
    static {
        for (ModSecOperator nf : ModSecOperator.values()) {
            s_map.put("@"+nf.name().toLowerCase(), nf);
        }
    }

    static ModSecOperator getInstance(String op)
    {
        ModSecOperator nf = s_map.get(op.toLowerCase());
        return nf;
    }
}
