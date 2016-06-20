package org.webheal.crawler;

import java.io.File;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

import au.com.bytecode.opencsv.CSVWriter;

public class ParamUtils  {
    private static final File DIR_ROOT = new File("./crawlerdiffs");

    private static final DateFormat FILE_NAME_FMT = new SimpleDateFormat("yyMMdd-HHmm-ssSSS");

    public static File saveParams(String site, Collection<PageFormParam> formParams) throws IOException
    {
        File dir = init(site);
        String fileName = FILE_NAME_FMT.format(new Date(System.currentTimeMillis()))+".csv";
        File file = new File(dir,fileName);
        CSVWriter writer = new CSVWriter(new FileWriter(file), ',');
        try {
            writer.writeNext(new String[]{"Form Action", "Form Name", "Form Method", "Input", "Page Uri", "Page Title"});
            for ( PageFormParam param : formParams ) {
                param.writeToCsv(writer);
            }
            writer.flush();
        } finally {
            writer.close();
        }
        return file;
    }
    
    public static File getSiteRoot(File rootDir,String site) {
        StringBuffer buf = new StringBuffer();
        for ( char c : site.toLowerCase().toCharArray() ) {
            if ( Character.isLowerCase(c)) {
                buf.append(c);
            }
        }
        return new File(rootDir, buf.toString());
    }
    public static void cleanup(String site) throws IOException {
        FileUtils.deleteDirectory(getSiteRoot(DIR_ROOT,site));
    }
    public static File init(String site) throws IOException {
        File file = getSiteRoot(DIR_ROOT,site);
        file.mkdirs();
        return file; 
    }

    public static long getLastCrawlTime(Logger logger, String site) throws IOException, ParseException {
        File dir = init(site);
        File[] files = dir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name)
            {
                return name.endsWith(".csv");
            }
        });
        Arrays.sort(files);
        if ( files == null || files.length == 0 ) {
            return -1;
        }
        File file = files[files.length-1];
        String name = file.getName();
        int idx = name.lastIndexOf('.');
        name = name.substring(0,idx);
        Date dt = FILE_NAME_FMT.parse(name);
        //logger.info("LastCrawl File : "+file.getName()+", "+name);
        return dt.getTime();
    }
    public static ParamChangeInfo getDiff(String site) throws IOException {
        File dir = init(site);
        File[] files = dir.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name)
            {
                return name.endsWith(".csv");
            }
        });
        Arrays.sort(files);
        if ( files.length < 1) {
            return null;
        }
        ParamChangeInfo info = new ParamChangeInfo(files[files.length-1],files.length > 1 ? files[files.length-2] : null);
        LinkedHashSet<String> first = new LinkedHashSet<String>();
        LinkedHashSet<String> second = new LinkedHashSet<String>();
        first.addAll(FileUtils.readLines(info.first));
        if ( info.second != null ) {
            second.addAll(FileUtils.readLines(info.second));
        }
        for ( String line : first ) {
            if ( !second.contains(line) ) {
                info.firstAdded.add(line);
            }
        }
        for ( String line : second ) {
            if ( !first.contains(line) ) {
                info.secondRemoved.add(line);
            }
        }
        return info;
    }
    static class ParamChangeInfo {
        public final File first;
        public final File second;
        Set<String> firstAdded = new LinkedHashSet<String>();
        Set<String> secondRemoved = new LinkedHashSet<String>();
        public ParamChangeInfo(File first, File second) {
            this.first = first;
            this.second = second;
        }

        public boolean isThereChange() {
            return ( firstAdded.size() > 0 || secondRemoved.size() > 0 ); 
        }
        
        public String toString() {
            if ( second == null ) {
                return "First time scan";
            }
            if ( isThereChange() ) {
                StringWriter str = new StringWriter();
                PrintWriter prt = new PrintWriter(str,true);
                prt.println("ADDED :"+firstAdded.size());
                for ( String line : firstAdded ) {
                    prt.println(line);
                }
                prt.println("");
                prt.println("REMOVED :"+secondRemoved.size());
                for ( String line : secondRemoved ) {
                    prt.println(line);
                }
                prt.flush();
                return str.toString();
            } else {
                return "There has been no parameter change since last scan";
            }
        }
    }
}