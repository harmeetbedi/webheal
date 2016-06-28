package org.webheal.scanner.attack;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.webheal.scanner.UrlResponse;
import org.webheal.scanner.visitor.AttackVisitor;

/**
 * Crawlers may extract email address from webpages and 
 */
public class EmailExposedAttack extends AbstractUrlAttack
{
    private static final String REGEX = "\\b[A-Z0-9._-]+@[A-Z0-9][A-Z0-9.-]{0,61}[A-Z0-9]\\.[A-Z.]{2,6}\\b";
    private static final Pattern REGEX_PAT = Pattern.compile(REGEX,Pattern.CASE_INSENSITIVE);
    protected boolean isExclude(String url) {
        return false;
    }
    @Override protected boolean attack(UrlParams src) throws Exception
    {
        //Matcher matcher = new Matc
        UrlResponse resp = uc.wget(src.url);
        String body = resp.resultBody;
        if ( StringUtils.isNotEmpty(body) ) {
            Matcher matcher = REGEX_PAT.matcher(body);
            return matcher.find();
        }
        return false;
    }
    public static void main(String[] args) {
        //String regex = "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}\\b";
        String input = "Hello HARMEET@KODEMUSE.COM test";
        Matcher matcher = REGEX_PAT.matcher(input);
        Set<String> emails = new HashSet<String>();
        while(matcher.find()) {
          emails.add(matcher.group());
        }
        System.out.println(emails);
    }
    @Override public void accept(AttackVisitor visitor) throws Exception
    {
        visitor.visitEmailExposedAttack(this);
    }
}
