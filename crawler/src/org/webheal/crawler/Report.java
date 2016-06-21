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

public class Report  {
    private static final DateFormat FILE_NAME_FMT = new SimpleDateFormat("yyMMdd.HHmm");
    private final File dir;
    private final File urlParamFile;
    private final File urlFile;
    private final File diffFile;

    private Report(File dir, String site) {
        this.dir = dir;
        Date dt = new Date(System.currentTimeMillis());
        String filePrefix = FILE_NAME_FMT.format(dt);
        urlParamFile = new File(dir,filePrefix+".urlparam.csv");
        urlFile = new File(dir,filePrefix+".url.txt");
        diffFile = new File(dir,filePrefix+".diff.txt");
    }

    public static Report init(File rootDir, String site) throws IOException {
        if ( rootDir == null ) {
            rootDir = new File("./crawler-report");
        }
        StringBuffer buf = new StringBuffer();
        for ( char c : site.toLowerCase().toCharArray() ) {
            if ( Character.isLowerCase(c)) {
                buf.append(c);
            }
        }
        File dir = new File(rootDir, buf.toString());
        dir.mkdirs();
        return new Report(dir,site); 
    }

    void saveReport(Collection<PageFormParam> formParams) throws IOException
    {
        CSVWriter writer = new CSVWriter(new FileWriter(urlParamFile), ',');
        try {
            writer.writeNext(new String[]{"Form Action", "Form Name", "Form Method", "Input", "Page Uri", "Page Title"});
            for ( PageFormParam param : formParams ) {
                param.writeToCsv(writer);
            }
            writer.flush();
        } finally {
            writer.close();
        }
    }
    
    public void writeCrawledLinks(Collection<String> urls) throws IOException
    {
        FileUtils.writeLines(urlFile, urls);
    }

    public void saveDiff(ParamChangeInfo diff) throws IOException
    {
        if ( diff == null || !diff.isThereChange()) {
            return;
        }

        FileUtils.write(diffFile, diff.toString());
    }
    
    public void cleanup(String site) throws IOException {
        FileUtils.deleteDirectory(dir);
    }

    public long getLastCrawlTime(Logger logger, String site) throws IOException, ParseException {
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
    public ParamChangeInfo getDiff() throws IOException {
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