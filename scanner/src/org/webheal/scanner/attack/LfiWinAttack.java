package org.webheal.scanner.attack;

import org.webheal.scanner.visitor.AttackVisitor;

public class LfiWinAttack extends DefaultUrlAttack
{

    @Override public void accept(AttackVisitor visitor) throws Exception
    {
        visitor.visitLfiWinAttack(this);
        
    }
}
