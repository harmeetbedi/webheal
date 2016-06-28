package org.webheal.scanner;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.webheal.scanner.attack.AbstractUrlAttack;
import org.webheal.util.PageFormParam;
import org.webheal.util.ServletParamHelper;
import org.webheal.util.Utils;

// runs crawler through rest api
public class WebMain
{
    public static void main(String[] args) throws Exception
    {
        File confDir = Utils.getConfigDir();
        Utils.initLogging(confDir, "crawler");
        int port = Integer.parseInt(System.getProperty("port", "8082"));
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
            if (!"/rest".equals(target)) {
                notFound(response);
                return;
            }
            baseRequest.setHandled(true);
            try {
                handleRest(request, response);
            } catch (Exception e) {
                if ( e instanceof IOException ) {
                    throw (IOException)e;
                } else {
                    throw new IOException(e);
                }
            }
        }
        private void handleRest(HttpServletRequest request, HttpServletResponse response) throws Exception
        {

            File confDir = Utils.getConfigDir();
            Utils.initLogging(confDir, "scanner");
            AppScanConfig conf = AppScanConfig.init(confDir,new ServletParamHelper(request));
            
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_OK);
            final DateFormat df = new SimpleDateFormat("HH:mm.ss");
            
            final PrintWriter out = response.getWriter();

            Map<String,List<PageFormParam>> pages = PageFormParam.readLatest(conf.crawlerDir);
            
            for ( Class<? extends AbstractUrlAttack> cls : conf.getAttacks() ) {
                AbstractUrlAttack attack = cls.newInstance();
                AppScanner.attack(attack,pages);
            }

            out.println(df.format(new Date()) + " DONE");
        }

        private void notFound(HttpServletResponse response) throws IOException
        {
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().println("Not Found");
        }
    }
}
