package org.webheal.scanner.visitor;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.webheal.scanner.AppScanConfig;
import org.webheal.scanner.attack.RobotTxtAttack;
import org.webheal.scanner.attack.SensitiveFileAttack;
import org.webheal.util.PageFormParam;

public class PagesToAttack extends NoopAttackVisitor
{
    private final Map<String, List<PageFormParam>> pages;
    private Collection<String> urls;
    
    public PagesToAttack(Map<String,List<PageFormParam>> pages) {
        this.pages = pages;
        this.urls = pages.keySet(); 
    }

    public Collection<String> getAttackUrls() { 
        return urls;
    }

    public void visitRobotTxtAttack(RobotTxtAttack attack) throws Exception
    {
        urls = Arrays.asList(AppScanConfig.get().getRobotsUrl());
    }
    public void visitSensitiveFileAttack(SensitiveFileAttack attack) throws Exception
    {
        urls = AppScanConfig.get().geSensitiveUrls();
    }
}
