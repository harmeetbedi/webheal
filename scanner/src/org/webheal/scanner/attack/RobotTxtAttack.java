package org.webheal.scanner.attack;

import java.net.URL;

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
    @Override protected boolean attack(UrlParams src) throws Exception
    {
        URL url = new URL(src.url);
        url = new URL(url.getProtocol(), url.getHost(),url.getPort(), "/robots.txt");
        nextAttackExists = false;
        try {
            UrlResponse resp = uc.wget(url.toExternalForm());
            return (resp.code == 200);
        } catch (Throwable e) {
            return false;
        }
    }
}
