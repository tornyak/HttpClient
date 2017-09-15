package com.tornyak.security;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import java.io.IOException;

public class SecureHttpClient {

    private HttpClient httpClient;


    public SecureHttpClient() throws Exception {

        SSLContext sslContext = SSLContexts.createDefault();
//                .custom()
//                .loadTrustMaterial(null,
//                (chain, authType) -> {
//                    System.out.println("isTrusted: authType: " + authType);
//                    System.out.println("chain: " + Arrays.toString(chain));
//                    return true;
//                })
//                .build();

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext,
                new String[]{"TLSv1.2"}, null, (hostname, sslSession) -> {
            System.out.println("verify hostname: " + hostname);
            return SSLConnectionSocketFactory.getDefaultHostnameVerifier().verify(hostname, sslSession);
        });

        HttpClientBuilder httpClientBuilder = HttpClients.custom()
            .setSSLSocketFactory(sslsf);

        httpClient = httpClientBuilder.build();
    }

    public HttpResponse execute(HttpUriRequest request) throws IOException, ClientProtocolException {
        return httpClient.execute(request);
    }
}
