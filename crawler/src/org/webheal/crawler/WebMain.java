package org.webheal.crawler;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.webheal.util.ServletParamHelper;
import org.webheal.util.Utils;

// runs crawler through rest api
public class WebMain
{
    public static void main(String[] args) throws Exception
    {
        File confDir = Utils.getConfigDir();
        Utils.initLogging(confDir, "crawler");
        int port = Integer.parseInt(System.getProperty("port", "8081"));
        Server server = new Server(port);
        server.setHandler(new RestHandler());
        server.start();
        server.join();
    }

    private static class RestHandler extends AbstractHandler
    {

        public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
                throws IOException, ServletException
        {
            if ( !"/rest".equals(target)) { 
                notFound(response);
                return;
            }
            
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_OK);
            final DateFormat df = new SimpleDateFormat("HH:mm.ss");
            baseRequest.setHandled(true);
            final PrintWriter out = response.getWriter();
            out.println(df.format(new Date())+" TARGET : [ "+target+" ]");

            File confDir = Utils.getConfigDir();
            Config conf = new Config(confDir);
            conf = new Config(conf,new ServletParamHelper(request));

            Crawler crawler = new Crawler(conf) {
                @Override protected void newPageFound(String url)
                {
                    super.newPageFound(url);
                    out.println(df.format(new Date())+" - "+url);
                }
            };
            crawler.crawl();
            crawler.report();
            out.println(df.format(new Date())+" DONE");
        }

        private void notFound(HttpServletResponse response) throws IOException
        {
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().println("Not Found");
        }
    }
}
