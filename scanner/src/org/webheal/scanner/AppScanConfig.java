package org.webheal.scanner;

import java.io.File;
import java.util.List;
import java.util.Properties;

import org.apache.commons.lang3.StringUtils;
import org.webheal.scanner.attack.AttackAndResponseMatch;
import org.webheal.scanner.attack.LFIAttackAndResponseMatch;
import org.webheal.util.Utils;

public class AppScanConfig
{
    public final String baseUrl;
    public final int connectionTimeout;
    public final int pausePageVisit;
    public final File crawlerDir;
    public final File reportDir;
    
    public final AttackAndResponseMatch blindSql;
    public final AttackAndResponseMatch xpath;
    public final AttackAndResponseMatch rfi;
    public final List<String> attackBig;
    public final List<String> blindAttack;
    public final List<String> dirListing;
    public final String proxyHost;
    public final int proxyPort;
    public final boolean proxyEnabled;
    public final LFIAttackAndResponseMatch lfiWin;
    public final LFIAttackAndResponseMatch lfiLinux;
    
    

    private AppScanConfig(File dir) throws Exception {
        Properties prop = Utils.load(new File(dir,"scanner.props"));
        pausePageVisit = Utils.toMillis(prop.getProperty("pause.pagevisit"));
        connectionTimeout = Utils.toMillis(prop.getProperty("conn.timeout"));
        baseUrl = prop.getProperty("scanner.rooturl");
        File reportDir = new File(prop.getProperty("scanner.report.dir"));
        this.reportDir = Utils.getSubDir(reportDir, baseUrl, true);
        proxyHost = prop.getProperty("proxy.host");
        proxyPort = StringUtils.isEmpty(proxyHost) ? -1 : Integer.parseInt(prop.getProperty("proxy.port","-1"));
        proxyEnabled = StringUtils.isNotEmpty(proxyHost) && (proxyPort > 0);
        File crawlerDir = new File(prop.getProperty("crawl.report.dir"));
        this.crawlerDir = Utils.getSubDir(crawlerDir, baseUrl, true);
        
        File appScanDir = new File(dir,"appscan");
        blindSql = new AttackAndResponseMatch(appScanDir,"sql.txt","sql_match.txt");
        xpath = new AttackAndResponseMatch(appScanDir,"xpath.txt","xpath_match.txt");
        rfi = new AttackAndResponseMatch(appScanDir,"rfi_vector.txt","rfi_match.txt");
        lfiWin = new LFIAttackAndResponseMatch(appScanDir,true);
        lfiLinux = new LFIAttackAndResponseMatch(appScanDir,false);
        attackBig = Utils.readLines(new File(appScanDir,"sqlbig.txt"));
        blindAttack = Utils.readLines(new File(appScanDir,"blindsql.txt"));
        dirListing = Utils.readLines(new File(appScanDir,"directory_listing_match.txt"));
    }
    
    private static AppScanConfig s_inst;
    public static AppScanConfig get() {
        return s_inst;
    }
    static AppScanConfig init(File dir) throws Exception {
        s_inst = new AppScanConfig(dir);
        return s_inst;
    }
}
