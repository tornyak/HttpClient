package com.tornyak.security;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.ssl.BrowserCompatHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;

/**
 * Created by vanja on 2017-08-28.
 */
public class SecureHttpClient implements HttpClient {

    private HttpClient httpClient;

    public SecureHttpClient() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, CertificateException, IOException {

        int connectionRequestTimeout = 15000;
        int connectionTimeout = 15000;
        int maxConnPerRoute = 2;
        int maxConnTotal = 400;
        int socketTimeout = 120000;

        RequestConfig requestConfig = RequestConfig.custom()
                .setSocketTimeout(socketTimeout)
                .setConnectTimeout(connectionTimeout)
                .setConnectionRequestTimeout(connectionRequestTimeout)
                .build();

        SSLContext sslContext = SSLContexts.createDefault();
                //.custom()
                //.loadTrustMaterial(null, (chain, authType) -> {
                //    System.out.println("isTrusted: authType: " + authType);
                //    System.out.println("chain: " + Arrays.toString(chain));
                //    return true;
                //})
                //.build();

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext,
                new String[]{"TLSv1.2"}, null, (hostname, sslSession) -> {
            System.out.println("verify hostname: " + hostname);
            return BrowserCompatHostnameVerifier.INSTANCE.verify(hostname, sslSession);
        });

        HttpClientBuilder httpClientBuilder = HttpClients.custom()
            .setMaxConnTotal(maxConnTotal)
            .setMaxConnPerRoute(maxConnPerRoute)
            .setDefaultRequestConfig(requestConfig)
            .setSSLSocketFactory(sslsf);

        httpClient = httpClientBuilder.build();
    }

    @Override
    public HttpParams getParams() {
        return httpClient.getParams();
    }

    @Override
    public ClientConnectionManager getConnectionManager() {
        return httpClient.getConnectionManager();
    }

    @Override
    public HttpResponse execute(HttpUriRequest request) throws IOException, ClientProtocolException {
        return httpClient.execute(request);
    }

    @Override
    public HttpResponse execute(HttpUriRequest request, HttpContext context) throws IOException, ClientProtocolException {
        return httpClient.execute(request, context);
    }

    @Override
    public HttpResponse execute(HttpHost target, HttpRequest request) throws IOException, ClientProtocolException {
        return httpClient.execute(target, request);
    }

    @Override
    public HttpResponse execute(HttpHost target, HttpRequest request, HttpContext context) throws IOException, ClientProtocolException {
        return httpClient.execute(target, request, context);
    }

    @Override
    public <T> T execute(HttpUriRequest request, ResponseHandler<? extends T> responseHandler) throws IOException, ClientProtocolException {
        return httpClient.execute(request, responseHandler);
    }

    @Override
    public <T> T execute(HttpUriRequest request, ResponseHandler<? extends T> responseHandler, HttpContext context) throws IOException, ClientProtocolException {
        return httpClient.execute(request, responseHandler, context);
    }

    @Override
    public <T> T execute(HttpHost target, HttpRequest request, ResponseHandler<? extends T> responseHandler) throws IOException, ClientProtocolException {
        return httpClient.execute(target, request, responseHandler);
    }

    @Override
    public <T> T execute(HttpHost target, HttpRequest request, ResponseHandler<? extends T> responseHandler, HttpContext context) throws IOException, ClientProtocolException {
        return httpClient.execute(target, request, responseHandler, context);
    }
}
