package org.webheal.scanner;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.webheal.scanner.attack.AbstractUrlAttack;
import org.webheal.scanner.attack.AspxDebugAttack;
import org.webheal.scanner.attack.AttackAndResponseMatch;
import org.webheal.scanner.attack.DefaultUrlAttack;
import org.webheal.scanner.attack.DirListingAttack;
import org.webheal.scanner.attack.EmailExposedAttack;
import org.webheal.scanner.attack.RFIAttack;
import org.webheal.scanner.attack.ResponseSplitAttack;
import org.webheal.scanner.attack.RobotTxtAttack;
import org.webheal.scanner.attack.SensitiveFileAttack;
import org.webheal.scanner.attack.XPathAttack;
import org.webheal.util.PageFormParam;
import org.webheal.util.Utils;

public class AppScanner
{
    public static void main(String[] args) throws Exception
    {
        File confDir = Utils.getConfigDir();
        Utils.initLogging(confDir, "scanner");
        AppScanConfig conf = AppScanConfig.init(confDir);

        AppScanner scanner = new AppScanner(conf);
        //System.out.println(scanner.pages);
//        scanner.xpathAttack();
//        scanner.rfiAttack();
//        scanner.responseSplitAttackAttack();
//        scanner.lfiWinAttack();
//        scanner.lfiLinuxAttack();
        //scanner.robotsTxtAttack();
        //scanner.aspxDebugAttack();
        //scanner.dirListingAttack();
        //scanner.sensitiveFilesAttack();
        //scanner.emailExposedAttack();
    }

    private final AppScanConfig conf;
    private final Map<String,List<PageFormParam>> pages;
    public AppScanner( AppScanConfig conf) throws Exception {
        this.conf = conf;
        pages = PageFormParam.readLatest(conf.crawlerDir);
    }

    // collects pages/links in target site. This can be done by crawling or using previous crawl results 
    // Links can be collected from crawl attempts if @param newCrawl = false or there are no previous crawl attempts for the site.
//    public void crawl(File reportDir, String site) throws Exception {
//        StringBuilder buf = new StringBuilder();
//        for ( char c : site.toLowerCase().toCharArray() ) {
//            if ( Character.isLowerCase(c)) {
//                buf.append(c);
//            }
//        }
//        File file = new File(reportDir, buf.toString());
//    }

    private void xpathAttack() throws Exception
    {
        attack(new XPathAttack(),conf.xpath);
    }
    
    private void rfiAttack() throws Exception
    {
        attack(new RFIAttack(),conf.rfi);
    }
    
    private void lfiWinAttack() throws Exception
    {
        attack(new DefaultUrlAttack(),conf.lfiWin);
    }
    
    private void lfiLinuxAttack() throws Exception
    {
        attack(new DefaultUrlAttack(),conf.lfiLinux);
    }
    
    private void responseSplitAttackAttack() throws Exception
    {
        attack(new ResponseSplitAttack(),conf.rfi);
    }
    private void aspxDebugAttack() throws Exception
    {
        attack(new AspxDebugAttack(),null);
    }
    private void dirListingAttack() throws Exception
    {
        attack(new DirListingAttack(),new AttackAndResponseMatch(conf.dirListing,null));
    }
    private void robotsTxtAttack() throws Exception
    {
        Collection<String> pagelist = Arrays.asList(conf.getRobotsUrl());
        attack(pagelist,new RobotTxtAttack(),null,-1);
    }
    private void sensitiveFilesAttack() throws Exception
    {
        attack(conf.geSensitiveUrls(), new SensitiveFileAttack(), null,-1);
    }
    private void emailExposedAttack() throws Exception
    {
        attack(new EmailExposedAttack(),null);
    }
    
    private void attack(AbstractUrlAttack attack,AttackAndResponseMatch conf) throws Exception {
        attack(pages.keySet(),attack,conf,1);
    }
    private void attack(Collection<String> pagelist,AbstractUrlAttack attack,AttackAndResponseMatch conf, int maxFailCount) throws Exception {
        int failCount = 0;
        attack.configure(conf);
        try {
            System.out.println(pagelist);
            for ( String pageUrl : pagelist ) {
                if ( !attack.hasNext() ) {
                    break;
                }
                boolean fail = attack.attack(pageUrl);
                if ( fail ) {
                    failCount++;
                    String result = String.format("Attack Exists (%s) : %s", attack.getClass().getSimpleName(),pageUrl);
                    System.out.println(result);
                    if ( maxFailCount > 0 && failCount >= maxFailCount ) {
                        break;
                    }
                }
            }
        } finally {
            attack.done();
        }
        if ( failCount == 0 ) {
            String result = String.format("Attack NotExists %s", attack.getClass().getSimpleName());
            System.out.println(result);
        }
    }
}
