package com.tornyak.security;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.fluent.Response;
import org.junit.Test;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;

public class SecureHttpClientTest {

    SecureHttpClient httpClient;

    public void SecureHttpClient() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        httpClient = new SecureHttpClient();
    }

    @Test
    public void validCertificate() throws Exception {
        Response resp = Request.Get("https://sha256.badssl.com/").execute();
        assertEquals(200, resp.handleResponse(response -> response.getStatusLine()).getStatusCode());
    }

    @Test(expected = SSLHandshakeException.class)
    public void expiredCertificate() throws Exception {
        Request.Get("https://expired.badssl.com/").execute();
    }

    @Test(expected = SSLPeerUnverifiedException.class)
    public void wrongHostCertificate() throws Exception {
        Request.Get("https://wrong.host.badssl.com/").execute().returnContent();
    }

    @Test(expected = SSLHandshakeException.class)
    public void selfSignedCertificate() throws Exception {
        Request.Get("https://self-signed.badssl.com/").execute().returnContent();
    }

    @Test(expected = SSLHandshakeException.class)
    public void untrustedRootCertificate() throws Exception {
        Request.Get("https://untrusted-root.badssl.com/").execute().returnContent();
    }

    @Test(expected = SSLHandshakeException.class)
    public void revokedCertificate() throws Exception {
        Request.Get("https://revoked.badssl.com/").execute().returnContent();
    }

    @Test(expected = SSLHandshakeException.class)
    public void pinningFailedCertificate() throws Exception {
        Request.Get("https://pinning-test.badssl.com/").execute().returnContent();
    }
}
