package org.webheal.modsec;

import java.util.ArrayList;
import java.util.List;

public class ModSecUtils
{
    public static List<String> tokenizeRuleParts(String src, char sep) {
        List<String> results = new ArrayList<String>();
        int len = src.length();
        for ( int i = 0 ; i < len ; i++ ) {
            char c = src.charAt(i);
            if ( c == '"' || c == '\'' ) {
                int endIdx = src.indexOf(c, i+1);
                if ( endIdx < 0 ) {
                    String msg = "Invalid rule. sep=["+sep+"], idx="+i+", src: "+src;
                    throw new RuntimeException(msg);
                }
                while ( true ) {
                    char prevChar = src.charAt( endIdx - 1 );
                    if ( prevChar == '\\' ) {
                        // escape char, find next idx
                        endIdx = src.indexOf(c, endIdx+1);
                        if ( endIdx < 0 ) {
                            String msg = "Invalid rule. sep=["+sep+"], idx="+i+", src: "+src;
                            throw new RuntimeException(msg);
                        }
                    } else {
                        break;
                    }
                }
                String item = src.substring(i, endIdx+1);
                results.add(item);
                i = endIdx;
            }
            else if ( c == sep ){
                continue;
            }
            else {
                int endIdx = src.indexOf(sep,i);
                final String item;
                if ( endIdx > 0) {
                    item = src.substring(i, endIdx);
                    i = endIdx;
                } else {
                    item = src.substring(i);
                    break;
                }
                results.add(item);
            }
        }
        return results;
    }
}
