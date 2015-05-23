package org.webheal.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

public class Utils
{
    public static long getTime(String str)
    {
        char c = str.charAt(str.length() - 1);
        long mult = 1L;
        if (Character.isLetter(c)) {
            if (c == 'h') {
                mult = 60 * 60 * 1000L;
            } else if (c == 'm') {
                mult = 60 * 1000L;
            } else if (c == 's') {
                mult = 1000L;
            }
            str = str.substring(0, str.length() - 1);
        }
        long value = Long.parseLong(str);
        return mult * value;
    }
    public static byte[] getByteArray(String fileName)
    {
        return getByteArray(new File(fileName));
    }

    public static byte[] getByteArray(File file)
    {
        try {
            return getByteArray(new FileInputStream(file));
        } catch (FileNotFoundException e) {
            return null;
        }
    }

    public static byte[] getByteArray(InputStream inputStream)
    {
        byte[] bytes = null;
        int totalLength = 0;
        byte[] tempBytes = new byte[1024];
        try {
            int length;
            while ((length = inputStream.read(tempBytes, 0, tempBytes.length)) != -1) {
                totalLength += length;
                if (totalLength - length > 0) {
                    byte[] newlyReadBytes = new byte[totalLength];
                    System.arraycopy(bytes, 0, newlyReadBytes, 0, totalLength - length);
                    bytes = newlyReadBytes;
                } else {
                    bytes = new byte[length];
                }
                System.arraycopy(tempBytes, 0, bytes, totalLength - length, length);
            }
        } catch (IOException e1) {
            return null;
        }
        return bytes;
    }

    public static int getIndex(byte[] src, int srcOffet, int srcLength, byte[] pattern, boolean firstOrLastMatch)
    {
        srcLength = Math.min(src.length, srcLength);
        int maxMatchStartIdx = srcLength - pattern.length;
        int matchIdx = -1;
        for (int i = srcOffet; i <= srcOffet + maxMatchStartIdx; i++) {
            boolean matchFound = true;
            for (int pi = 0; pi < pattern.length; pi++) {
                if ((i + pi >= src.length) || src[i + pi] != pattern[pi]) {
                    matchFound = false;
                    break;
                }
            }
            if (matchFound) {
                matchIdx = i;
            }
            if (matchFound && firstOrLastMatch) {
                break;
            }
        }
        return matchIdx;
    }

    public static int getIndex(byte[] src, byte[] pattern)
    {
        return getIndex(src, 0, src.length, pattern, true);
    }

    public static void main(String[] args)
    {
        String data = "HTTP/1.1 200 OK";
        byte[] pattern = "HTTP/1".getBytes();
        int idx = getIndex(data.getBytes(), 0, pattern.length, pattern, true);
        System.out.println("match = " + idx);
    }

    public static String convert(Throwable t)
    {
        StringWriter str = new StringWriter();
        PrintWriter prt = new PrintWriter(str, true);
        t.printStackTrace(prt);
        prt.flush();
        return str.toString();
    }
    public static String indent(int level)
    {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < level; i++) {
            buf.append("    ");
        }
        return buf.toString();
    }

    public static String removeQuoted(String src)
    {
        StringBuffer buf = new StringBuffer();
        Character ignoreChar = null;
        for (char c : src.toCharArray()) {
            if (ignoreChar == null) {
                if (c == '\'' || c == '\"') {
                    ignoreChar = c;
                } else {
                    buf.append(c);
                }
            } else {
                if (c == ignoreChar) {
                    ignoreChar = null;
                }
            }
        }
        return buf.toString();
    }

    public static List<String> tokenize(String src, char c, boolean trim)
    {
        List<String> list = new ArrayList<String>();
        StringTokenizer tokens = new StringTokenizer(src, c + "");
        while (tokens.hasMoreTokens()) {
            String str = tokens.nextToken();
            if (trim) {
                str = str.trim();
            }
            if (StringUtils.isNotEmpty(str)) {
                list.add(str);
            }
        }
        return list;
    }
    public static void append(File file, String line) throws IOException
    {
        FileWriter out = new FileWriter(file, true);
        try {
            PrintWriter prt = new PrintWriter(out);
            prt.println(line);
            prt.flush();
        } finally {
            IOUtils.closeQuietly(out);
        }
    }
    public static void appendQuietly(File file, String line)
    {
        try {
            append(file, line);
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    public static Map<String,String> readConfig(String file) throws Exception
    {
        Map<String,String> prop = new LinkedHashMap<String,String>();
        FileInputStream fin = new FileInputStream(file);
        try {
            List<String> lines = IOUtils.readLines(fin);
            for ( String line : lines ) {
                String[] parts = line.trim().split("=");
                if ( parts.length == 2 && !parts[0].startsWith("#")) {
                    prop.put(parts[0].trim().toLowerCase(),parts[1].trim());
                }
            }
        } catch (Exception ex) {
            IOUtils.closeQuietly(fin);
        }
        return prop;
    }
    public static Set<String> toSet(String str, String splitRegex)
    {
        Set<String> set = new HashSet<String>();
        if ( StringUtils.isNotEmpty(str)) {
            for (String part : str.split(splitRegex)) {
                set.add(part);
            }
        }
        return set;
    }
}
