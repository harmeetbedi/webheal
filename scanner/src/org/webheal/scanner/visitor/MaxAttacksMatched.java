package org.webheal.scanner.visitor;

import org.webheal.scanner.attack.SensitiveFileAttack;

// number of attacks found that would cause probing for attack to cease 
public class MaxAttacksMatched extends NoopAttackVisitor
{
    private int threshold = 1;
    public void visitSensitiveFileAttack(SensitiveFileAttack attack) throws Exception {
        // no limit. browse each oe
        threshold = -1;
    }
    
    public int getThreshold() {
        return threshold;
    }
}
