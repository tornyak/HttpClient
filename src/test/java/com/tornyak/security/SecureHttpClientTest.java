package com.tornyak.security;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.junit.Test;

import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;

public class SecureHttpClientTest {

    SecureHttpClient httpClient;

    public SecureHttpClientTest() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        httpClient = new SecureHttpClient();
    }

    @Test
    public void validCertificate() throws Exception {
        HttpResponse response = httpClient.execute(new HttpGet("https://sha256.badssl.com/"));
        assertEquals(200, response.getStatusLine().getStatusCode());
    }

    @Test(expected = SSLHandshakeException.class)
    public void expiredCertificate() throws Exception {
        httpClient.execute(new HttpGet("https://expired.badssl.com/"));
    }

    @Test
    public void wrongHostCertificate() throws Exception {
        httpClient.execute(new HttpGet("https://wrong.host.badssl.com/"));
    }

    @Test(expected = SSLHandshakeException.class)
    public void selfSignedCertificate() throws Exception {
        httpClient.execute(new HttpGet("https://self-signed.badssl.com/"));
    }

    @Test(expected = SSLHandshakeException.class)
    public void untrustedRootCertificate() throws Exception {
        httpClient.execute(new HttpGet("https://untrusted-root.badssl.com/"));
    }

    @Test(expected = SSLHandshakeException.class)
    public void revokedCertificate() throws Exception {
        httpClient.execute(new HttpGet("https://pinning-test.badssl.com/"));
    }

    @Test(expected = SSLHandshakeException.class)
    public void pinningFailedCertificate() throws Exception {
        httpClient.execute(new HttpGet("https://pinning-test.badssl.com/"));
    }
}
