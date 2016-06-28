package org.webheal.scanner.attack;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.webheal.scanner.visitor.AttackVisitor;

public class DirListingAttack extends AbstractUrlAttack
{
    protected boolean isExclude(String url)
    {
        return false;
    }
    private List<String> getDirUrls(UrlParams src) throws Exception {
        List<String> list = new ArrayList<String>();
        URL url = new URL(src.url);
        String file = url.getFile();
        int idx = file.lastIndexOf('?');
        if ( idx > 0 ) {
            file = file.substring(0, idx);
        }
        idx = file.lastIndexOf('/');
        if ( idx > 0 ) {
            String dir = file.substring(0, idx+1);
            String leaf = file.substring(idx+1);
            URL urla = new URL(url.getProtocol(),url.getHost(),url.getPort(),dir);
            list.add(urla.toExternalForm());
            if( !leaf.contains(".")) {
                URL urlb = new URL(url.getProtocol(),url.getHost(),url.getPort(),file);
                list.add(urlb.toExternalForm());
            }
        }
        return list;
    }
    @Override protected boolean attack(UrlParams src) throws Exception
    {
        for ( String url : getDirUrls(src)) {
            if ( checkForAttack(url)) {
                return true;
            }
        }
        return false;
    }
    private boolean checkForAttack(String url) {
        if ( StringUtils.isEmpty(url)) {
            return false;
        }
        if ( alreadyDone.contains(url)) {
            return false;
        }
        System.out.println("dirurl - "+url);
        alreadyDone.add(url);
        String data = wget(url);
        if ( StringUtils.isEmpty(data)) {
            return false;
        }
        for ( String attackLine : conf.attacks ) {
            for ( String attack : attackLine.split("&") ) {
                if ( data.contains(attack) ) {
                    return true;
                }
            }
        }
        return false;
    }
    @Override public void accept(AttackVisitor visitor) throws Exception
    {
        visitor.visitDirListingAttack(this);
        
    }
}
