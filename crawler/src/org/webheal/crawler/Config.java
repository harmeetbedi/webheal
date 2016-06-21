package org.webheal.crawler;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collection;
import java.util.Properties;
import java.util.TreeSet;

import org.webheal.util.Utils;

public class Config
{
    public final int maxUrls;
    public final int maxDepth;
    public final String domain;
    public final String rootUrl;
    public final String reportDir;
    public final Collection<String> ignoreExts;
    Config(File dir) throws IOException {
        Properties prop = Utils.load(new File(dir,"crawler.props"));
        this.maxUrls = Integer.parseInt(prop.getProperty("crawl.maxurls")); 
        this.maxDepth = Integer.parseInt(prop.getProperty("crawl.maxdepth")); 
        this.rootUrl = prop.getProperty("crawl.rooturl");
        this.reportDir = prop.getProperty("crawl.report.dir");
        ignoreExts = new TreeSet<String>();
        ignoreExts.addAll(Arrays.asList(prop.getProperty("crawl.ignore.exts").split(",")));
        this.domain = new URL(this.rootUrl).getHost();
    }
    @Override public String toString() {
        return String.format("maxUrls=%d, maxDepth=%d, rootUrl=%s, ignoreExts=%s",maxUrls,maxDepth,rootUrl,ignoreExts.toString());
    }
}
