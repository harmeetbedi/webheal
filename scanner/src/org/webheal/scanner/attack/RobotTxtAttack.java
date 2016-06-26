package org.webheal.scanner.attack;

import org.webheal.scanner.UrlResponse;

/**
 * https://exchange.xforce.ibmcloud.com/vulnerabilities/1533
 * 
 * The robots.txt file is commonly placed in the root directory of a system's Web server
 * 
 * This is not a vulnerability. Administrators should review the contents of the robots.txt file to check if the information is consistent with
 * the policies of their organization.
 */
public class RobotTxtAttack extends AbstractUrlAttack
{
    protected boolean isExclude(String url) {
        return false;
    }
    @Override protected boolean attack(UrlParams src) throws Exception
    {
        UrlResponse resp = uc.wget(src.url);
        return resp.isResponseOk();
    }
}
