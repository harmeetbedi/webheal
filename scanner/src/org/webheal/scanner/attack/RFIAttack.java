package org.webheal.scanner.attack;

import org.webheal.scanner.visitor.AttackVisitor;

public class RFIAttack extends DefaultUrlAttack
{

    @Override public void accept(AttackVisitor visitor) throws Exception
    {
        visitor.visitRFIAttack(this);
    }
}
