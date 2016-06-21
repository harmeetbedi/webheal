package org.webheal.crawler;

import java.io.File;

import org.webheal.util.Utils;

public class Main
{
    public static void main(String[] args) throws Exception
    {
        File confDir = Utils.getConfigDir();
        Utils.initLogging(confDir, "crawler");
        Config conf = new Config(confDir);
        Crawler crawler = new Crawler(conf);
        crawler.crawl();
        crawler.report();
    }
}
