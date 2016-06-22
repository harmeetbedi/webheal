package org.webheal.scanner.attack;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.webheal.util.Utils;

// most attacks have set of params you hit site with and text in response body
public class AttackAndResponseMatch {
    public List<String> attacks;
    public List<String> matches;
    public AttackAndResponseMatch(List<String> attacks,List<String> matches) {
        this.attacks = attacks;
        this.matches = matches;
    }
    
    public AttackAndResponseMatch(File attackFile, File matchesFile) throws Exception {
        attacks = Utils.readLines(attackFile);
        matches = Utils.readLines(matchesFile);
    }
    public AttackAndResponseMatch(File dir, String attackFile, String matchesFile) throws Exception {
        if ( attackFile != null ) {
            attacks = Utils.readLines(new File(dir,attackFile));
        } else {
            attacks = new ArrayList<String>();
        }
        if ( matchesFile != null ) {
            matches = Utils.readLines(new File(dir,matchesFile));
        } else {
            matches = new ArrayList<String>();
        }
    }
}
