package org.webheal.crawler;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;
import org.webheal.crawler.Report.ParamChangeInfo;
import org.webheal.util.PageFormParam;
import org.webheal.util.Utils;

public class Crawler
{
    private WebDriver driver;
    // private final WebDriver driver = new FirefoxDriver();
    private final Map<String, List<PageFormParam>> crawledLinks = new HashMap<String, List<PageFormParam>>();
    private final TreeMap<String, PageFormParam> formParams = new TreeMap<String, PageFormParam>();
    private int crawlCount;
    private final Config conf;
    private final Report report;

    public Crawler(Config conf) throws IOException {
        this.conf = conf;
        File dir = Utils.getSubDir(new File(conf.reportDir), conf.rootUrl, true);
        report = new Report(dir); 
    }

    public void crawl()
    {
        log("crawl " + conf.domain + ", starting at " + conf.rootUrl);
        driver = new HtmlUnitDriver(false);
        log("driver initialized");
        try {
            crawl(0, conf.rootUrl);
        } finally {
            driver.close();
        }
    }

    public void crawl(int depth, String url)
    {
        if (conf.maxDepth > 0 && depth > conf.maxDepth) {
            return;
        }
        if (conf.maxUrls > 0 && crawlCount > conf.maxUrls) {
            return;
        }
        log("crawl " + url);
        if (!isLinkCrawlable(url)) {
            return;
        }
        driver.get(url);
        crawlCount++;
        url = driver.getCurrentUrl().toLowerCase();
        if (crawledLinks.containsKey(url)) {
            return;
        }
        String title = driver.getTitle();
        log(depth + "," + crawlCount + ": " + url + ", " + title);
        // System.out.println(driver.getPageSource());

        Set<String> links = new LinkedHashSet<String>();
        List<WebElement> allLinks = driver.findElements(By.tagName("frame"));
        for (WebElement link : allLinks) {
            String href = link.getAttribute("src");
            if (href == null) {
                continue;
            }
            // System.out.println("href:"+href);
            links.add(href);
        }
        allLinks = driver.findElements(By.tagName("a"));
        for (WebElement link : allLinks) {
            String href = link.getAttribute("href");
            if (href == null) {
                continue;
            }
            // System.out.println("href:"+href);
            links.add(href);
        }
        List<WebElement> forms = driver.findElements(By.tagName("form"));
        List<PageFormParam> urlFormParams = new ArrayList<PageFormParam>();
        for (WebElement form : forms) {
            String formAction = form.getAttribute("action");
            String formName = form.getAttribute("name");
            if (StringUtils.isEmpty(formName)) {
                formName = form.getAttribute("id");
            }
            String formMethod = form.getAttribute("method");
            collectFormParams(url, urlFormParams, title, formName, formAction, formMethod, form, "input", "textarea", "select", "button");
        }
        crawledLinks.put(url, urlFormParams);
        for (String link : links) {
            crawl(depth + 1, link);
        }
    }

    private void log(Object msg)
    {
        Logger.getLogger("crawler").info(msg);
        msg = (new Date(System.currentTimeMillis())) + " : " + msg;
        System.out.println(msg);
    }

    private void collectFormParams(String url, List<PageFormParam> urlFormParams, String title, String formName, String formAction,
            String formMethod, WebElement form, String... tagNames)
    {
        for (String tagName : tagNames) {
            List<WebElement> inputs = driver.findElements(By.tagName(tagName));
            for (WebElement input : inputs) {
                String name = input.getAttribute("name");
                if (name != null && name.length() > 0) {
                    PageFormParam param = new PageFormParam(url, title, formName, formAction, formMethod, name);
                    log(param);
                    formParams.put(param.description, param);
                    urlFormParams.add(param);
                }
            }
        }
    }

    private boolean isLinkCrawlable(String url)
    {
        url = url.toLowerCase();
        int idx = url.indexOf('#');
        if (idx > 0) {
            url = url.substring(0, idx);
        }
        if (crawledLinks.containsKey(url)) {
            return false;
        }
        idx = url.lastIndexOf('.');
        if (idx > 0) {
            String ext = url.substring(idx + 1);
            if (conf.ignoreExts.contains(ext)) {
                return false;
            }
        }
        try {
            URL u = new URL(url);
            String host = u.getHost();
            if (host.equals(conf.domain)) {
                return true;
            } else {
                return false;
            }
        } catch (MalformedURLException e) {
            return false;
        }
    }

    public Collection<String> getCrawledLinks()
    {
        return crawledLinks.keySet();
    }

    public void report() throws IOException
    {
        report.saveReport(formParams.values());
        ParamChangeInfo diff = report.getDiff();
        report.writeCrawledLinks(getCrawledLinks());
        report.saveDiff(diff);
    }
}