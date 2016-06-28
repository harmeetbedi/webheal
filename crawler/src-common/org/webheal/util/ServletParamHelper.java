package org.webheal.util;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;

public class ServletParamHelper
{
    private final HttpServletRequest request;
    public ServletParamHelper(HttpServletRequest request) {
        this.request = request;
    }
    public String getString(String key,String defaultValue) {
        String value = request.getParameter(key);
        if ( StringUtils.isEmpty(value) ) {
            return defaultValue;
        } else {
            return value;
        }
    }
    public int getInt(String key,int defaultValue) {
        String value = request.getParameter(key);
        if ( StringUtils.isEmpty(value) ) {
            return defaultValue;
        } else {
            return Integer.parseInt(value);
        }
    }
    public boolean getBool(String key,boolean defaultValue) {
        String value = request.getParameter(key);
        if ( StringUtils.isEmpty(value) ) {
            return defaultValue;
        } else {
            return Boolean.parseBoolean(value);
        }
    }
    public long getLong(String key,long defaultValue) {
        String value = request.getParameter(key);
        if ( StringUtils.isEmpty(value) ) {
            return defaultValue;
        } else {
            return Long.parseLong(value);
        }
    }
    public float getFloat(String key,float defaultValue) {
        String value = request.getParameter(key);
        if ( StringUtils.isEmpty(value) ) {
            return defaultValue;
        } else {
            return Float.parseFloat(value);
        }
    }
}
