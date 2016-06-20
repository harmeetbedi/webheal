package org.webheal.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;

public class Utils
{
    public static int toMillis(String value) throws IOException
    {
        final int len = value.length();
        if (len == 0) {
            return 0;
        }
        char lastChar = value.charAt(len - 1);
        if (Character.isDigit(lastChar)) {
            return Integer.parseInt(value);
        }
        int millis = Integer.parseInt(value.substring(0,len-1));
        if ( lastChar == 's' ) {
            millis *= 1000;
        }
        if ( lastChar == 'm' ) {
            millis *= (1000 * 60);
        }
        if ( lastChar == 'h' ) {
            millis *= (1000 * 60 * 60);
        }
        return millis;
    }
    public static Properties load(File file) throws IOException
    {
        Properties prop = new Properties();
        FileInputStream fin = new FileInputStream(file);
        try {
            prop.load(fin);
        } finally {
            IOUtils.closeQuietly(fin);
        }
        return prop;
    }
    
    public static boolean httpGet(HttpClient hc, String url, File out) throws IOException {
        HttpGet get = new HttpGet(url);
        HttpResponse resp = hc.execute(get);
        int code = resp.getStatusLine().getStatusCode();
        boolean ok = false;
        if ( code == HttpURLConnection.HTTP_OK) {
            String resultBody = EntityUtils.toString(resp.getEntity());
            EntityUtils.consume(resp.getEntity());
            FileUtils.writeStringToFile(out, resultBody);
            ok  = true;
        }
        EntityUtils.consume(resp.getEntity());
        return ok;
    }
    public static String httpGet(HttpClient hc, String url) throws IOException {
        HttpGet get = new HttpGet(url);
        HttpResponse resp = hc.execute(get);
        int code = resp.getStatusLine().getStatusCode();
        if ( code == HttpURLConnection.HTTP_OK) {
            String resultBody = EntityUtils.toString(resp.getEntity());
            EntityUtils.consume(resp.getEntity());
            return resultBody;
        }
        EntityUtils.consume(resp.getEntity());
        return null;
    }

    public static String getMD5Digest(File file) throws Exception
    {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        FileInputStream fin = new FileInputStream(file);
        try {
            byte[] buf = new byte[16 * 1024];
            while (true) {
                int count = fin.read(buf);
                if (count > 0) {
                    digest.update(buf, 0, count);
                }
                if (count < buf.length) {
                    break;
                }
            }
        } finally {
            IOUtils.closeQuietly(fin);
        }
        byte[] sha = digest.digest();
        String hex = Utils.toHex(sha);
        return hex;
    }
    /** hex encode byte array */
    public static String toHex(byte[] ba)
    {
        StringBuffer hexData = new StringBuffer();
        for (byte b : ba) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hex = "0" + hex;
            }
            hexData.append(hex);
        }
        return hexData.toString();
    }
    public static List<String> readLines(File file) throws Exception {
        Reader in = new FileReader(file);
        try {
            List<String> set = new ArrayList<String>();
            readLines(in,set,true,true,true);
            return set;
        } finally {
            IOUtils.closeQuietly(in);
        }
    }

    private static void readLines(Reader fin, Collection<String> callback, boolean trim, boolean ignoreEmpty, boolean close)
            throws Exception
    {
        if (close) {
            try {
                readLines(fin, callback, trim, ignoreEmpty, false);
                return;
            } finally {
                IOUtils.closeQuietly(fin);
            }
        }
        BufferedReader reader = new BufferedReader(fin);
        while (true) {
            String line = reader.readLine();
            if (line == null) {
                break;
            }
            if (trim) {
                line = line.trim();
            }
            if (ignoreEmpty && line.length() == 0) {
                continue;
            }
            callback.add(line);
        }
    }
    public static boolean hasPattern(String data, Collection<String> matches)
    {
        if (StringUtils.isEmpty(data)) {
            return false;
        }
        for (String pat : matches) {
            if (data.matches(pat)) {
                return true;
            }
        }
        return false;
    }
}
