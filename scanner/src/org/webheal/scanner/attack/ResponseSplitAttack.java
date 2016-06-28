package org.webheal.scanner.attack;

import org.apache.http.Header;
import org.webheal.scanner.visitor.AttackVisitor;
import org.webheal.util.NameValue;

public class ResponseSplitAttack extends AbstractUrlAttack
{
    @Override protected boolean attack(UrlParams src) throws Exception
    {
        if (src.params.isEmpty()) {
            return false;
        }
        String[] attacks = { "%0d%0aRandomHeader:NO", "%0d%0a%20RandomHeader:NO" };//{ "%3f%0d%0aX-RESPSPLIT-Safe:%20NO" };
        for (NameValue pnv : src.params) {
            for (String attack : attacks) {
                String trgUrl = src.replaceParamValue(pnv.name, attack);
                if ( alreadyDone.contains(trgUrl) ) {
                    //System.out.println("    (alreadydone) "+trgUrl);
                    return false;
                }
                alreadyDone.add(trgUrl);
                for ( Header header : wgetHeaders(trgUrl) ) {
                    if ( header.getName().equalsIgnoreCase("RandomHeader") && header.getValue().equalsIgnoreCase("NO") ) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    @Override public void accept(AttackVisitor visitor) throws Exception
    {
        visitor.visitResponseSplitAttack(this);
        
    }


}
