package org.webheal.scanner.attack;

import org.apache.commons.lang3.StringUtils;

/**
 * https://exchange.xforce.ibmcloud.com/vulnerabilities/1533
 * 
 * The robots.txt file is commonly placed in the root directory of a system's Web server
 * 
 * This is not a vulnerability. Administrators should review the contents of the robots.txt file to check if the information is consistent with
 * the policies of their organization.
 */
public class AspxDebugAttack extends AbstractUrlAttack
{
    protected boolean isExclude(String url)
    {
        int idx = url.indexOf('?');
        if (idx > 0) {
            url = url.substring(idx);
        }
        url = url.toLowerCase();
        boolean allowed = url.endsWith(".aspx") || url.endsWith(".asmx") || url.endsWith(".master") || url.endsWith(".svc") || url.endsWith(".asax");
        return !allowed;
    }
    @Override protected boolean attack(UrlParams src) throws Exception
    {
        nextAttackExists = false;
        String url = src.url;
        int idx = url.indexOf('?');
        if (idx > 0) {
            url = url.substring(idx);
        }
        String resp = wget(url,true);
        return ( StringUtils.isNotEmpty(resp) && resp.trim().toLowerCase().startsWith("ok") );
    }
}
