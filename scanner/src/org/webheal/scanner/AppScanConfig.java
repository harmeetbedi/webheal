package org.webheal.scanner;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.webheal.scanner.attack.AbstractUrlAttack;
import org.webheal.scanner.attack.AspxDebugAttack;
import org.webheal.scanner.attack.AttackAndResponseMatch;
import org.webheal.scanner.attack.DirListingAttack;
import org.webheal.scanner.attack.EmailExposedAttack;
import org.webheal.scanner.attack.LFIAttackAndResponseMatch;
import org.webheal.scanner.attack.LfiLinuxAttack;
import org.webheal.scanner.attack.LfiWinAttack;
import org.webheal.scanner.attack.RFIAttack;
import org.webheal.scanner.attack.ResponseSplitAttack;
import org.webheal.scanner.attack.RobotTxtAttack;
import org.webheal.scanner.attack.SensitiveFileAttack;
import org.webheal.scanner.attack.XPathAttack;
import org.webheal.util.ServletParamHelper;
import org.webheal.util.Utils;

public class AppScanConfig
{
    private static Map<String,Class<? extends AbstractUrlAttack>> s_map = new TreeMap<String,Class<? extends AbstractUrlAttack>>();
    static {
        s_map.put("xpath", XPathAttack.class);
        s_map.put("rfi", RFIAttack.class);
        s_map.put("responsesplit", ResponseSplitAttack.class);
        s_map.put("lfiwin", LfiWinAttack.class);
        s_map.put("lfilinux", LfiLinuxAttack.class);
        s_map.put("robot", RobotTxtAttack.class);
        s_map.put("aspxdebug", AspxDebugAttack.class);
        s_map.put("dirlisting", DirListingAttack.class);
        s_map.put("sensitivefile", SensitiveFileAttack.class);
        s_map.put("emailexposed", EmailExposedAttack.class);
    }

    public final String baseUrl;
    public final int connectionTimeout;
    public final int pausePageVisit;
    private final File crawlerRootDir;
    public final File crawlerDir;
    public final File reportDir;
    
    public final AttackAndResponseMatch blindSql;
    public final AttackAndResponseMatch xpath;
    public final AttackAndResponseMatch rfi;
    public final List<String> attackBig;
    public final List<String> blindAttack;
    public final List<String> dirListing;
    public final List<String> sensitiveFiles;
    public final List<String> okResponseFor404;
    public final Set<String> attacks = new LinkedHashSet<String>();
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
        this.crawlerRootDir = new File(prop.getProperty("crawl.report.dir"));
        this.crawlerDir = Utils.getSubDir(crawlerRootDir, baseUrl, true);
        
        File appScanDir = new File(dir,"appscan");
        blindSql = new AttackAndResponseMatch(appScanDir,"sql.txt","sql_match.txt");
        xpath = new AttackAndResponseMatch(appScanDir,"xpath.txt","xpath_match.txt");
        rfi = new AttackAndResponseMatch(appScanDir,"rfi_vector.txt","rfi_match.txt");
        lfiWin = new LFIAttackAndResponseMatch(appScanDir,true);
        lfiLinux = new LFIAttackAndResponseMatch(appScanDir,false);
        attackBig = Utils.readLines(new File(appScanDir,"sqlbig.txt"));
        blindAttack = Utils.readLines(new File(appScanDir,"blindsql.txt"));
        dirListing = Utils.readLines(new File(appScanDir,"directory_listing_match.txt"));
        sensitiveFiles = Utils.readLines(new File(appScanDir,"sensitive.txt"));
        okResponseFor404 = Utils.readLines(new File(appScanDir,"is404.txt"));
        String attacksProp = prop.getProperty("attacks");
        if ( StringUtils.isNotEmpty(attacksProp) ) {
            List<String> parts = Arrays.asList(attacksProp.split(","));
            attacks.addAll(parts);
        }
        if ( attacks.isEmpty() ) {
            attacks.addAll(s_map.keySet());
        }
    }
    
    public AppScanConfig(AppScanConfig src, ServletParamHelper req) throws MalformedURLException {
        String domain = new URL(src.baseUrl).getHost();
        domain = req.getString("domain", domain);
        this.baseUrl = "http://"+domain+"/";
        this.connectionTimeout = req.getInt("timeout", src.connectionTimeout);
        this.pausePageVisit = req.getInt("pause", src.pausePageVisit);
        this.crawlerRootDir = src.crawlerRootDir;
        this.crawlerDir = Utils.getSubDir(crawlerRootDir, baseUrl, true);
        this.reportDir = src.reportDir;
        String attacks = req.getString("attacks","");
        if ( StringUtils.isNotEmpty(attacks) ) {
            List<String> parts = Arrays.asList(attacks.split(","));
            this.attacks.clear();
            this.attacks.addAll(parts);
        } else {
            this.attacks.addAll(src.attacks);
        }
        
        this.blindSql = src.blindSql;
        this.xpath = src.xpath;
        this.rfi = src.rfi;
        this.attackBig = src.attackBig;
        this.blindAttack = src.blindAttack;
        this.dirListing = src.dirListing;
        this.sensitiveFiles = src.sensitiveFiles;
        this.okResponseFor404 = src.okResponseFor404;
        this.proxyHost = src.proxyHost;
        this.proxyPort = src.proxyPort;
        this.proxyEnabled = src.proxyEnabled;
        this.lfiWin = src.lfiWin;
        this.lfiLinux = src.lfiLinux;
    }

    private static AppScanConfig s_inst;
    public static AppScanConfig get() {
        return s_inst;
    }
    static AppScanConfig init(File dir) throws Exception {
        s_inst = new AppScanConfig(dir);
        return s_inst;
    }
    static AppScanConfig init(File dir, ServletParamHelper req) throws Exception {
        AppScanConfig conf = new AppScanConfig(dir);
        conf = new AppScanConfig(conf,req);
        s_inst = conf;
        return s_inst;
    }
    public Collection<String> geSensitiveUrls() throws MalformedURLException
    {
        List<String> list = new ArrayList<String>();
        URL base = new URL(baseUrl);
        for ( String item : sensitiveFiles ) {
            String file = item.startsWith("/") ? item : "/"+item;
            URL url = new URL(base.getProtocol(),base.getHost(), base.getPort(),file);
            list.add(url.toExternalForm());
        }
        return list;
    }
    public String getRobotsUrl() throws MalformedURLException {
        URL base = new URL(baseUrl);
        URL url = new URL(base.getProtocol(), base.getHost(),base.getPort(), "/robots.txt");
        return url.toExternalForm();
    }

    public List<Class<? extends AbstractUrlAttack>> getAttacks() {
        List<Class<? extends AbstractUrlAttack>> list = new ArrayList<Class<? extends AbstractUrlAttack>> ();
        for ( String key : attacks ) {
            Class<? extends AbstractUrlAttack> cls = s_map.get(key);
            if ( cls != null ) {
                list.add(cls);
            }
        }
        return list;
    }
}
