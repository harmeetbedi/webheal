package org.webheal.scanner.attack;

import org.webheal.util.NameValue;
import org.webheal.util.Utils;

public class DefaultUrlAttack extends AbstractUrlAttack
{
    @Override protected boolean attack(UrlParams src) throws Exception
    {
        if (src.params.isEmpty()) {
            return false;
        }
        for (NameValue pnv : src.params) {
            for (String attack : conf.attacks) {
                String trgUrl = src.replaceParamValue(pnv.name, attack);
                if ( alreadyDone.contains(trgUrl) ) {
                    //System.out.println("    (alreadydone) "+trgUrl);
                    return false;
                }
                alreadyDone.add(trgUrl);
                String data = wget(trgUrl);
                if (Utils.hasPattern(data, conf.matches)) {
                    return true;
                }
            }
        }
        return false;
    }
}
