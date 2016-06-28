package org.webheal.scanner.visitor;

import org.webheal.scanner.attack.AspxDebugAttack;
import org.webheal.scanner.attack.DirListingAttack;
import org.webheal.scanner.attack.EmailExposedAttack;
import org.webheal.scanner.attack.LfiLinuxAttack;
import org.webheal.scanner.attack.LfiWinAttack;
import org.webheal.scanner.attack.RFIAttack;
import org.webheal.scanner.attack.ResponseSplitAttack;
import org.webheal.scanner.attack.RobotTxtAttack;
import org.webheal.scanner.attack.SensitiveFileAttack;
import org.webheal.scanner.attack.XPathAttack;
import org.webheal.util.Logable;

public class NoopAttackVisitor extends Logable implements AttackVisitor
{
    public void visitXPathAttack(XPathAttack attack) throws Exception { }

    public void visitRFIAttack(RFIAttack attack) throws Exception { }

    public void visitResponseSplitAttack(ResponseSplitAttack attack) throws Exception { }

    public void visitLfiWinAttack(LfiWinAttack attack) throws Exception { }

    public void visitLfiLinuxAttack(LfiLinuxAttack attack) throws Exception { }

    public void visitRobotTxtAttack(RobotTxtAttack attack) throws Exception { }

    public void visitAspxDebugAttack(AspxDebugAttack attack) throws Exception { }

    public void visitDirListingAttack(DirListingAttack attack) throws Exception { }

    public void visitSensitiveFileAttack(SensitiveFileAttack attack) throws Exception { }

    public void visitEmailExposedAttack(EmailExposedAttack attack) throws Exception { }
}
