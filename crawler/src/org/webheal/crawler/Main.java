package org.webheal.crawler;

import java.io.File;

import org.apache.log4j.xml.DOMConfigurator;

public class Main
{
    public static void main(String[] args) throws Exception
    {
        File configDir = new File("./config");
        if ( !configDir.isDirectory() ) {
            System.out.println("Invalid user directory. Config directory not found");
            System.exit(1);
        }
        new File("./logs").mkdirs();
        File logConfig = new File(configDir, "log4j.xml");
        System.out.println("logconfig : "+logConfig.getCanonicalPath());
        DOMConfigurator.configureAndWatch(logConfig.getAbsolutePath());
        //File confFile = new File(configDir,"wafcrawler.props");

        String rootUrl = (args.length > 0) ? args[0] : "http://www.indusface.com/"; //https://www.corpretail.com/RetailBank/";
        //String rootDir = (args.length > 1) ? args[1] : "/Users/harmeet/tmp/crawlerdiffs";
        String emailToList = (args.length > 1) ? args[1] : "harmeet@kodemuse.com";
        int maxDepth = (args.length > 2) ? Integer.parseInt(args[2]) : 1;
        int maxUrls = (args.length > 3) ? Integer.parseInt(args[3]) : 50;
        Crawler.crawl(rootUrl, emailToList, maxDepth, maxUrls);
    }
}
