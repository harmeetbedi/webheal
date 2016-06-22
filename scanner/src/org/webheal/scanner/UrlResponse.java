package org.webheal.scanner;

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

}
