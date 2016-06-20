package org.webheal.crawler;

import java.net.MalformedURLException;
import java.net.URL;

import au.com.bytecode.opencsv.CSVWriter;

public class PageFormParam implements Comparable<PageFormParam>
{
    final String pageUri;
    final String pageTitle;
    final String formAction;
    final String formName;
    final String formMethod;
    final String input;
    final String description;
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
        this.pageUri = file;
        this.pageTitle = pageTitle;
        this.formAction = formAction;
        this.formMethod = formMethod;
        this.formName = formName;
        this.input = name;
        this.description = formAction + ", " + formName + ", " + formMethod+", "+input + ", " + pageUri + ", " + pageTitle; 
    }
    public void writeToCsv(CSVWriter writer)
    {
        writer.writeNext(new String[]{formAction, formName, formMethod, input, pageUri, pageTitle});

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
}