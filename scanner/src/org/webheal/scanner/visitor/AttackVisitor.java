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

public interface AttackVisitor
{
    void visitXPathAttack(XPathAttack attack) throws Exception;

    void visitRFIAttack(RFIAttack attack) throws Exception;

    void visitResponseSplitAttack(ResponseSplitAttack attack) throws Exception;

    void visitLfiWinAttack(LfiWinAttack attack) throws Exception;

    void visitLfiLinuxAttack(LfiLinuxAttack attack) throws Exception;

    void visitRobotTxtAttack(RobotTxtAttack attack) throws Exception;

    void visitAspxDebugAttack(AspxDebugAttack attack) throws Exception;

    void visitDirListingAttack(DirListingAttack attack) throws Exception;

    void visitSensitiveFileAttack(SensitiveFileAttack attack) throws Exception;

    void visitEmailExposedAttack(EmailExposedAttack attack) throws Exception;
}
