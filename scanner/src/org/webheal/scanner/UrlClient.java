package org.webheal.scanner;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.RedirectStrategy;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.conn.BasicClientConnectionManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;

import org.webheal.util.Logable;

public class UrlClient extends Logable 
{
    private final HttpClient hc;

    public UrlClient() {
        HttpParams params = new BasicHttpParams();
        AppScanConfig conf = AppScanConfig.get();
        HttpConnectionParams.setConnectionTimeout(params, conf.connectionTimeout);
        HttpConnectionParams.setSoTimeout(params, conf.connectionTimeout);
        DefaultHttpClient hc = new DefaultHttpClient(params) {
            @Override protected ClientConnectionManager createClientConnectionManager()
            {
                try {
                    final SchemeRegistry registry = new SchemeRegistry();
                    TrustStrategy trustStrategy = new TrustStrategy() {
                        public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException
                        {
                            return true;
                        }
                    };
                    // TrustManager mgr = new TrustManager() {
                    // TrustManager[] trustmanagers = new
                    // SSLContext sslcontext = SSLContext.getInstance("TLS");
                    // sslcontext.init(null, null, null);
                    SSLSocketFactory sslFactory = new SSLSocketFactory(trustStrategy, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                    // registry.register(new Scheme("https", 443, sslFactory));
                    int httpPort = Integer.parseInt(System.getProperty("http.port", "80"));
                    int httpsPort = Integer.parseInt(System.getProperty("https.port", "443"));
                    registry.register(new Scheme("https", httpsPort, sslFactory));
                    registry.register(new Scheme("http", httpPort, PlainSocketFactory.getSocketFactory()));
                    // System.out.println("port(plain:"+httpPort+",ssl:"+httpsPort+")");
                    BasicClientConnectionManager connManager = new BasicClientConnectionManager(registry);
                    return connManager;
                } catch (Exception e) {
                    log().error("trust manager setup failed", e);
                    return null;
                }
            }
        };
        RedirectStrategy strategy = new DefaultRedirectStrategy() {
            protected boolean isRedirectable(final String method) {
                return false;
            }
        };
        hc.setRedirectStrategy(strategy);
        if (conf.proxyEnabled) {
            HttpHost proxy = new HttpHost(conf.proxyHost, conf.proxyPort);
            hc.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
        }
        this.hc = hc;
    }
    
    public void close() {
        try { hc.getConnectionManager().shutdown(); } catch(Throwable t) { }
    }

    public UrlResponse wget(String url) throws IOException {
        return wget(url,false);
    }
    public UrlResponse wget(String url, boolean debug) throws IOException {
        //AppScanConfig conf = AppScanConfig.get();
        final HttpGet get;
        if (debug) {
            get = new HttpGet(url) { 
                public String getMethod() {
                    return "DEBUG";
                }
            };
            get.setHeader("Command", "stop-debug");
        } else {
            get = new HttpGet(url);
        }
        
        HttpResponse resp = hc.execute(get);
        int code = resp.getStatusLine().getStatusCode();
        if ( code == HttpURLConnection.HTTP_OK) {
            String resultBody = EntityUtils.toString(resp.getEntity());
            EntityUtils.consume(resp.getEntity());
            return new UrlResponse(code, resp.getAllHeaders(), resultBody);
        }
        EntityUtils.consume(resp.getEntity());
        return new UrlResponse(code, resp.getAllHeaders(), null);
    }
}
