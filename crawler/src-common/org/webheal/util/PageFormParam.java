package org.webheal.util;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import au.com.bytecode.opencsv.CSVReader;
import au.com.bytecode.opencsv.CSVWriter;

public class PageFormParam extends Logable implements Comparable<PageFormParam>
{
    public final String pageUri;
    public final String pageTitle;
    public final String formAction;
    public final String formName;
    public final String formMethod;
    public final String input;
    public final String description;
    public final String url;
    private PageFormParam(String[] values) {
        int idx = 0;
        url = values[idx++];
        formAction = values[idx++];
        formName = values[idx++];
        formMethod = values[idx++];
        input = values[idx++];
        pageUri = values[idx++];
        pageTitle = values[idx++];
        this.description = formAction + ", " + formName + ", " + formMethod+", "+input + ", " + pageUri + ", " + pageTitle; 
    }
    public PageFormParam(String url, String pageTitle, String formName, String formAction, String formMethod, String name) {
        String file = url;
        try {
            file = new URL(url).getFile();
        } catch (MalformedURLException e) {
        }
        if (pageTitle == null) {
            pageTitle = "";
        }
        if (formAction == null) {
            formAction = "";
        }
        if (formName == null) {
            formName = "";
        }
        if ( formMethod == null ) { 
            formMethod = "";
        }
        this.url = url;
        this.pageUri = file;
        this.pageTitle = pageTitle;
        this.formAction = formAction;
        this.formMethod = formMethod;
        this.formName = formName;
        this.input = name;
        this.description = formAction + ", " + formName + ", " + formMethod+", "+input + ", " + pageUri + ", " + pageTitle; 
    }
    public void writeCsvRow(CSVWriter writer)
    {
        writer.writeNext(new String[]{url,formAction, formName, formMethod, input, pageUri, pageTitle});

    }
    public String toString()
    {
        return description;
    }
    public int compareTo(PageFormParam obj)
    {
        int result = 0;
        if (result == 0) {
            result = formAction.compareTo(obj.formAction);
        }
        if (result == 0) {
            result = formName.compareTo(obj.formName);
        }
        if (result == 0) {
            result = formMethod.compareTo(obj.formMethod);
        }
        if (result == 0) {
            result = input.compareTo(obj.input);
        }
        if (result == 0) {
            result = pageUri.compareTo(obj.pageUri);
        }
        if (result == 0) {
            result = pageTitle.compareTo(obj.pageTitle);
        }
        return result;
    }
    public static void writeCsv(File reportFile, Collection<PageFormParam> formParams) throws IOException
    {
        CSVWriter writer = new CSVWriter(new FileWriter(reportFile), ',');
        try {
            writer.writeNext(new String[]{"URL","Form Action", "Form Name", "Form Method", "Input", "Page Uri", "Page Title"});
            for ( PageFormParam param : formParams ) {
                param.writeCsvRow(writer);
            }
            writer.flush();
        } finally {
            writer.close();
        }
    }
    public static Map<String,List<PageFormParam>> readLatest(File dir) throws Exception
    {
        Map<String,List<PageFormParam>> map = new LinkedHashMap<String,List<PageFormParam>>();
        if ( !dir.exists() || !dir.isDirectory()) {
            return map;
        }
        Collection<String> urls = Utils.readLines(Utils.getLastFileWithSuffix(dir,".url.txt"));
        for ( String url : urls ) {
            map.put(url, new ArrayList<PageFormParam>());
        }
        File file = Utils.getLastFileWithSuffix(dir,".urlparam.csv");
        if ( file == null ) {
            return map;
        }
        CSVReader reader = new CSVReader(new FileReader(file));
        try {
            String[] values = null;
            boolean firstLine = true;
            while ((values = reader.readNext()) != null) {
                if ( firstLine ) {
                    firstLine = false;
                    continue;
                }
                if ( values.length != 7 ) {
                    continue;
                }
                PageFormParam param = new PageFormParam(values);
                List<PageFormParam> list = map.get(param.url);
                if ( list != null ) {
                    list.add(param);
                } else {
                    Logger.getLogger(PageFormParam.class).error("Url does not exist in list of urls : "+param.url);
                }
            }
        } finally {
            reader.close();
        }
        return map;
    }
}