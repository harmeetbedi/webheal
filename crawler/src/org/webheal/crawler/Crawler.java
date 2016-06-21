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

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.htmlunit.HtmlUnitDriver;

public class Crawler
{
    private WebDriver driver;
    // private final WebDriver driver = new FirefoxDriver();
    private final Map<String, List<PageFormParam>> crawledLinks = new HashMap<String, List<PageFormParam>>();
    private final TreeMap<String, PageFormParam> formParams = new TreeMap<String, PageFormParam>();
    private int crawlCount;
    private final Config conf;

    public Crawler(Config conf) throws MalformedURLException {
        this.conf = conf;
    }

    // public static void crawl(String rootUrl, int maxDepth, int maxUrls) throws IOException, EmailException
    // {
    // Crawler crawler = new Crawler(rootUrl,maxDepth,maxUrls);
    // crawler.log("crawl "+rootUrl+" "+maxDepth+" "+maxUrls);
    // crawler.crawl();
    // ParamUtils.saveParams(rootUrl,crawler.formParams.values());
    // ParamUtils.ParamChangeInfo diff = ParamUtils.getDiff(rootUrl);
    // if ( diff != null ) {
    // final String subject;
    // String body = diff.toString();
    // List<File> attachments = new ArrayList<File>();
    // if ( diff.isThereChange() ) {
    // subject = "Param Diff "+rootUrl;
    // attachments.add(diff.first);
    // if ( diff.second != null ) {
    // attachments.add(diff.second);
    // }
    // } else {
    // subject = "No Param Diff "+rootUrl;
    // }
    // }
    // }

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
    public void writeCrawledLinks(File file) throws IOException
    {
        File dir = file.getParentFile();
        dir.mkdirs();
        FileUtils.writeLines(file, crawledLinks.keySet());
    }

    public void report() throws IOException
    {
        ParamUtils.saveParams(conf.rootUrl, formParams.values());
        ParamUtils.ParamChangeInfo diff = ParamUtils.getDiff(conf.rootUrl);
        ParamUtils.saveDiff(conf.rootUrl, diff);
    }
}