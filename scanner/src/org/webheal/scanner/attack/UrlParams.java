package org.webheal.scanner.attack;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

import org.webheal.util.NameValue;

class UrlParams
{
    public final String url;
    private final String urlNoParams;
    final List<NameValue> params = new ArrayList<NameValue>();
    UrlParams(UrlParams src) {
        this.url = src.url;
        this.urlNoParams = src.urlNoParams;
        this.params.addAll(src.params);
    }
    // attacks often replace a single value with attack vector
    public String replaceParamValue(String name, String attack) throws UnsupportedEncodingException
    {
        StringBuilder str = new StringBuilder();
        str.append(urlNoParams);
        str.append("?");
        for (NameValue nv : params) {
            str.append(nv.name);
            str.append("=");
            if (nv.name.equals(name)) {
                str.append(URLEncoder.encode(attack, "UTF-8"));
            } else {
                str.append(nv.value);
            }
        }
        String result = str.toString();
        return result;
    }
    UrlParams(String url) {
        this.url = url;
        int idx = url.indexOf('?');
        if (idx <= 0) {
            urlNoParams = null;
            return;
        }
        urlNoParams = url.substring(0, idx);
        String query = url.substring(idx+1);
        String[] nvList = query.split("&");
        for (String nv : nvList) {
            int nvSep = nv.indexOf('=');
            if (nvSep <= 0) {
                continue;
            }
            String name = nv.substring(0, nvSep);
            String value = nv.substring(nvSep + 1);
            NameValue item = new NameValue(name, value);
            params.add(item);
        }
    }
    UrlParams makeCopy()
    {
        return new UrlParams(this);
    }
}
