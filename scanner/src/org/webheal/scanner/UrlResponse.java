package org.webheal.scanner;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;

public class UrlResponse
{

    public final String resultBody;
    public final Header[] allHeaders;
    public final int code;

    public UrlResponse(int code, Header[] allHeaders, String resultBody) {
        this.code = code;
        this.allHeaders = allHeaders;
        this.resultBody = resultBody; 
    }

    public boolean isResponseOk() {
        if ( code != 200 ) {
            return false;
        }
        if ( StringUtils.isNotEmpty(resultBody) ) {
            for ( String str : AppScanConfig.get().okResponseFor404 ) {
                if ( resultBody.contains(str) ) {
                    return false;
                }
            }
        }
        return true;
    }
}
