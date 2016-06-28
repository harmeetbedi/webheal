package org.webheal.scanner.visitor;

import org.webheal.scanner.AppScanConfig;
import org.webheal.scanner.attack.AttackAndResponseMatch;
import org.webheal.scanner.attack.DirListingAttack;
import org.webheal.scanner.attack.LfiLinuxAttack;
import org.webheal.scanner.attack.LfiWinAttack;
import org.webheal.scanner.attack.RFIAttack;
import org.webheal.scanner.attack.ResponseSplitAttack;
import org.webheal.scanner.attack.XPathAttack;

public class ConfigureAttack extends NoopAttackVisitor
{

    public void visitXPathAttack(XPathAttack attack) throws Exception
    {
        attack.configure(AppScanConfig.get().xpath);
    }

    public void visitRFIAttack(RFIAttack attack) throws Exception
    {
        attack.configure(AppScanConfig.get().rfi);
    }

    public void visitResponseSplitAttack(ResponseSplitAttack attack) throws Exception
    {
        attack.configure(AppScanConfig.get().rfi);
    }

    public void visitLfiWinAttack(LfiWinAttack attack) throws Exception
    {
        attack.configure(AppScanConfig.get().lfiWin);
    }

    public void visitLfiLinuxAttack(LfiLinuxAttack attack) throws Exception
    {
        attack.configure(AppScanConfig.get().lfiLinux);
    }

    public void visitDirListingAttack(DirListingAttack attack) throws Exception
    {
        attack.configure(new AttackAndResponseMatch(AppScanConfig.get().dirListing, null));
    }
}
