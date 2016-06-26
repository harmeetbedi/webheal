package org.webheal.scanner.attack;

import org.webheal.scanner.UrlResponse;

/**
 * checks if there sensitive files are exposed.
 * 
 * Test is done aginst known sentitive paths. If 200 Ok is retured and body does not indicate error due to not_found resource, it is a
 * vulnerability
 */
public class SensitiveFileAttack extends AbstractUrlAttack
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
