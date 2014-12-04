package org.webheal.modsec;

import java.net.HttpCookie;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.log4j.Logger;

import pcap.reconst.output.HttpRequestResponse;

public abstract class ModSecVariable<T>
{

    private static final Logger LOG = Logger.getLogger(ModSecVariable.class);

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
    
    private T value;
    public final T getValue(HttpRequestResponse http) {
        if ( value == null ) {
            value = getValueNoCache(http);
        }
        return value;
    }
    protected abstract T getValueNoCache(HttpRequestResponse http);

    public static ModSecVariable<?> newInstance(String name) {
        String clsName = ModSecVariable.class.getName()+"$"+name;
        try  {
            Class<? extends ModSecVariable<?>> cls = (Class<? extends ModSecVariable<?>>)Class.forName(clsName);
            ModSecVariable<?> var = (ModSecVariable<?>)cls.newInstance();
//            Constructor<? extends ModSecVariable> ctor = cls.getDeclaredConstructor(String.class,Boolean.class,String.class);
//            ModSecVariable var = ctor.newInstance(name,not,qualifier);
            return var;
        } catch(Throwable t) {
            LOG.error("Variable not implemented : "+name+", "+clsName);
            return null;
        }
    }

    // get value and put in cache
    public static Object getValue(HttpRequestResponse http, ModSecVariable<?> var,Map<HttpRequestResponse,Map<String,Object>> cache) {
        Map<String,Object> varValue = cache.get(http);
        if (varValue == null) {
            varValue = new HashMap<String,Object>();
            cache.put(http, varValue);
        }
        String name = var.getClass().getName();
        int idx = name.lastIndexOf('$');
        name = name.substring(idx+1);
        Object value = varValue.get(name);
        if ( value == null ) {
            value = var.getValue(http);
            varValue.put(name, value);
        }
        return value;
    }
    
    public static class ARGS extends ModSecVariable<Map<String,String>> {
        @Override public Map<String,String> getValueNoCache(HttpRequestResponse http)
        {
            String uri = new REQUEST_URI().getValue(http);
            //value = URLDecoder.decode(value,http.getRequest().getHeaders().getCharset().name());
            if ( "POST".equals(http.getRequestMethod() ) ) {
                String type = http.getRequest().getContentType();
                if ( type != null ) {
                    type = type.toLowerCase();
                }
                if ( type.contains("x-www-form-urlencoded") ) {
                    String body = http.getRequest().getBody();
                    String prefix = "?";
                    if ( uri.contains("?")) {
                        prefix = "&";
                    }
                    if ( body.startsWith("&") || body.startsWith("?")) {
                        body = body.substring(1);
                    }
                    uri = uri + prefix + body;
                }
            }
            int idx = uri.indexOf('?');
            if ( idx >= 0 ) {
                uri = uri.substring(idx+1);
            }
            List<NameValuePair> list = URLEncodedUtils.parse(uri, http.getRequest().getHeaders().getCharset());
            Map<String,String> value = new LinkedHashMap<String,String>();
            for ( NameValuePair nv : list ) {
                value.put(nv.getName(),nv.getValue());
            }
            return value;
        }
    }
    
    public static class ARGS_NAMES extends ModSecVariable<Set<String>> {
        @Override public Set<String> getValueNoCache(HttpRequestResponse http)
        {
            Map<String,String> map = (Map<String,String>)new ARGS().getValue(http);
            return map.keySet();
        }
    }
    public static class QUERY_STRING extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            String value = new REQUEST_URI().getValue(http);
            int idx = value.indexOf('?');
            if ( idx >= 0 ) {
                value = value.substring(idx+1);
            } else {
                value = "";
            }
            return value;
        }
    }
    
    public static class REQUEST_BODY extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            return http.getRequest().getBody();
        } 
    }
    public static class REQUEST_URI extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            return http.getRequestUri();
        } 
    }
    public static class REMOTE_ADDR extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            return http.conn.getDstIp().getHostAddress();
        } 
    }
    public static class REQUEST_METHOD extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            return http.getRequestMethod();
        } 
    }
    public static class RESPONSE_BODY extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            return http.getResponse().getBody();
        } 
    }
    public static class RESPONSE_CONTENT_LENGTH extends ModSecVariable<Integer> {
        @Override public Integer getValueNoCache(HttpRequestResponse http)
        {
            return http.getResponse().getHeaders().getContentLength();
        } 
    }
    public static class RESPONSE_CONTENT_TYPE extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            return http.getResponse().getHeaders().getContentType();
        } 
    }
    public static class RESPONSE_STATUS extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            return http.getResponseStatus();
        } 
    }
    public static class REQUEST_COOKIES extends ModSecVariable<Map<String,String>> {
        @Override public Map<String,String> getValueNoCache(HttpRequestResponse http)
        {
            List<HttpCookie> list = http.getRequestCookies();
            Map<String,String> value = new LinkedHashMap<String,String>();
            for ( HttpCookie hc : list ) {
                value.put(hc.getName(), hc.getValue());
            }
            return value;
        } 
    }
    public static class REQUEST_COOKIES_NAMES extends ModSecVariable<Set<String>> {
        @Override public Set<String> getValueNoCache(HttpRequestResponse http)
        {
            Map<String,String> map = (Map<String,String>)new REQUEST_COOKIES().getValue(http);
            return map.keySet();
        } 
    }
    public static class REQUEST_HEADERS extends ModSecVariable<Map<String,String>> {
        @Override public Map<String,String> getValueNoCache(HttpRequestResponse http)
        {
            return http.getRequest().getHeaders().getMap();
        } 
    }
    public static class REQUEST_HEADERS_NAMES extends ModSecVariable<Set<String>> {
        @Override public Set<String> getValueNoCache(HttpRequestResponse http)
        {
            Map<String,String> map = (Map<String,String>)new REQUEST_HEADERS().getValue(http);
            return map.keySet();
        } 
    }
    public static class RESPONSE_HEADERS extends ModSecVariable<Map<String,String>> {
        @Override public Map<String,String> getValueNoCache(HttpRequestResponse http)
        {
            return http.getResponse().getHeaders().getMap();
        } 
    }
    public static class RESPONSE_HEADERS_NAMES extends ModSecVariable<Set<String>> {
        @Override public Set<String> getValueNoCache(HttpRequestResponse http)
        {
            Map<String,String> map = (Map<String,String>)new RESPONSE_HEADERS().getValue(http);
            return map.keySet();
       } 
    }
    public static class REQUEST_LINE extends ModSecVariable<String> {
        @Override public String getValueNoCache(HttpRequestResponse http)
        {
            String value = http.getRequest().getHeaders().getFirstKey();
            return value;
       } 
    }
    
    
    // REQUEST_PROTOCOL, REQUEST_BASENAME, RESPONSE_PROTOCOL
}