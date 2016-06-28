package org.webheal.scanner;

import java.io.File;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.webheal.scanner.attack.AbstractUrlAttack;
import org.webheal.scanner.visitor.ConfigureAttack;
import org.webheal.scanner.visitor.MaxAttacksMatched;
import org.webheal.scanner.visitor.PagesToAttack;
import org.webheal.util.PageFormParam;
import org.webheal.util.Utils;

public class AppScanner
{
    public static void main(String[] args) throws Exception
    {
        File confDir = Utils.getConfigDir();
        Utils.initLogging(confDir, "scanner");
        AppScanConfig conf = AppScanConfig.init(confDir);
        Map<String,List<PageFormParam>> pages = PageFormParam.readLatest(conf.crawlerDir);
        
        for ( Class<? extends AbstractUrlAttack> cls : conf.getAttacks() ) {
            AbstractUrlAttack attack = cls.newInstance();
            attack(attack,pages);
        }
    }
    public static void attack(AbstractUrlAttack attack,Map<String,List<PageFormParam>> pages) throws Exception {
        attack.accept(new ConfigureAttack());

        PagesToAttack pagesToAttack = new PagesToAttack(pages);
        attack.accept(pagesToAttack);
        
        Collection<String> urls = pagesToAttack.getAttackUrls();
        MaxAttacksMatched maxAttacksMatched = new MaxAttacksMatched();
        int maxAttacks = maxAttacksMatched.getThreshold();

        attack(urls,attack, maxAttacks);
    }
    private static void attack(Collection<String> pagelist,AbstractUrlAttack attack, int maxFailCount) throws Exception {
        int failCount = 0;
        try {
            //System.out.println(pagelist);
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

//    private final AppScanConfig conf;
//    private final Map<String,List<PageFormParam>> pages;
//    public AppScanner( AppScanConfig conf) throws Exception {
//        this.conf = conf;
//        pages = PageFormParam.readLatest(conf.crawlerDir);
//    }
//
}
