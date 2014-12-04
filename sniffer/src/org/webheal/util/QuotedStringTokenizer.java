/*
 *  Copyright (C) 2007-2010 Christian Bockermann <chris@jwall.org>
 *
 *  This file is part of the  web-audit  library.
 *
 *  web-audit library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The  web-audit  library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package org.webheal.util;

import java.util.ArrayList;
import java.util.List;

import org.webheal.modsec.ModSecUtils;


/**
 * <p>
 * This class implements a split-method which takes care of quoted strings, i.e. there will be no
 * split within a char sequence that is surrounded by quotes (single or double quotes). These sequences
 * are simply skipped.
 * </p>
 * 
 * @author Christian Bockermann &lt;chris@jwall.org&gt;
 */
public class QuotedStringTokenizer {
    public static void main(String[] args) {
        String line = "SecRule REQUEST_LINE \"@contains /comment.aspx\" \"chain,log,deny,status:403,phase:2,block,t:none,t:urlDecodeUni,capture,logdata:'%{args.cfile}',severity:'5',id:1,msg:'IndusGuard Patch: XSS Web Attack Found!',tag:'WEB_ATTACK/XSS_ATTACK',tag:'WASCTC/WASC-19',tag:'OWASP_TOP_10/A1',tag:'OWASP_AppSensor/CIE1',tag:'PCI/6.5.2'\"";
        line = "SecRule \"ARGS:cfile\" \"([ # \\\" ` ' ( ) ; -- \' \\\"])\" \"ctl:auditLogParts=+E \"";
        List<String> parts = splitRespectQuotes(line,' ');
        List<String> parts2 = ModSecUtils.tokenizeRuleParts(line, ' ');
        System.out.println(parts.size()+" , "+parts2.size());
    }
    
    public static List<String> splitRespectQuotes( String input, char sep ){
//        if ( input != null ) {
//            throw new RuntimeException("splitRespectQuotes");
//        }
        List<String> results = new ArrayList<String>();
        int last = 0;
        int i = 0;
        
        int len = input.length();
        while( i < len ){
            char c = input.charAt( i );
            
            
            // we skip quoted substrings 
            //
            int startIdx = i;
            if( c == '"' || c == '\'' ){
                do {
                    i++;
                    //char d = input.charAt( i );
                } while( i < len && (input.charAt( i ) != c || input.charAt( i - 1 ) == '\\' ) );
            }
            int endIdx = i;
            if ( endIdx != startIdx ) {
                String ignored = input.substring(startIdx, endIdx+1);
                System.out.println("IGNORED > "+ignored);
            }
            
            // if we hit a separating character, we found another token
            //
            if( input.indexOf( sep, i ) == i  || i+1 == input.length() ){
                final String item;
                if( i + 1 == len ) {
                    item = input.substring( last, i + 1 );
                }
                else {
                    item = input.substring( last, i );
                }
                results.add( item );
                last = i + 1;
            }
            
            i++;
        }
        
        return results;
    }
}