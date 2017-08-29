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
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by vanja on 2017-08-28.
 */
public class SecureHttpClient implements HttpClient {

    private HttpClient httpClient;

    private static final String SOME_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDpTCCAo2gAwIBAgIJAO7U5lrBQm8iMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNV\n" +
            "BAYTAlNFMQ4wDAYDVQQIDAVLaXN0YTESMBAGA1UEBwwJU3RvY2tob2xtMREwDwYD\n" +
            "VQQKDAhFcmljc3NvbjEPMA0GA1UECwwGQXRoZW5hMRIwEAYDVQQDDAlBdGhlbmEg\n" +
            "Q0EwHhcNMTYwOTA5MTUxMDQ2WhcNMTcwOTA5MTUxMDQ2WjBpMQswCQYDVQQGEwJT\n" +
            "RTEOMAwGA1UECAwFS2lzdGExEjAQBgNVBAcMCVN0b2NraG9sbTERMA8GA1UECgwI\n" +
            "RXJpY3Nzb24xDzANBgNVBAsMBkF0aGVuYTESMBAGA1UEAwwJQXRoZW5hIENBMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApKkQc4YjNKEMa57E6h4nrtvl\n" +
            "bHAFAVv6FcafoJTvy8IFfMtCxRO3iOjAhwaB0FU/d2+zF/GXPrO/Oy3zpyoOesc4\n" +
            "qChx7X0qnrUPveen4OC+PYec84t2SbA79vQeXeIcu+DYhgArHieF9ETZTBeqv4Jv\n" +
            "ng3KDl8HjnMHWbv5fm8lxyK8+pRRp9XAUWp9ILph6o0+DImoSBJx0OYukHGlKWNK\n" +
            "djnagd1pX/n//9l0e+86IeQGYJqK0U4MdK85U3zqjUJY2lM2/Zmad6gTkvukEp8h\n" +
            "2fI8pleA3GO2G9dP329jPCLbe+3AwOraZeKSiMnwTZennLpHw6SpoZG7pOAGpQID\n" +
            "AQABo1AwTjAdBgNVHQ4EFgQUr8hqy1ycSET7PbE4Jc+wbBq5sF8wHwYDVR0jBBgw\n" +
            "FoAUr8hqy1ycSET7PbE4Jc+wbBq5sF8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B\n" +
            "AQsFAAOCAQEAHUq/0Vn7jt1EB8vntXmr1mlZWI/auVZ6FvZ/fnht5GiNbEd+18X8\n" +
            "BCTuTD4Goo6MAxlWJZNm/Fbxk9vxJPbUKlcPrfJdjUbBCxit9XOtUe1SIlcW0tlU\n" +
            "tfgE0WO0hwJ+L3D3e1qT+r3f6HeTEIJRalw0H6UjK1ilCaXp2mbruTcQh6WPDgoC\n" +
            "FFsWfiiKDT4jS7LtbrWXVKm8t/WZLoBZ3PcE0nWDuWJUvFIGBTjflzSsg10MfDvj\n" +
            "39+d5FjU74TwmVYgO9C1uQCpbGOyJnxRStdqlwH5rEY+NMyxLIRH7JLeydJUaOLb\n" +
            "Q027q9WsqQkRV/Yb65rzWEyCJ4CdtlcteA==\n" +
            "-----END CERTIFICATE-----\n";

    private static final String ENTITY_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIFSzCCBDOgAwIBAgIQTI4YcUs0516Nrvvo9kw6gjANBgkqhkiG9w0BAQsFADCB\n" +
            "kDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n" +
            "A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxNjA0BgNV\n" +
            "BAMTLUNPTU9ETyBSU0EgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBD\n" +
            "QTAeFw0xNjA3MDcwMDAwMDBaFw0xNzA5MDUyMzU5NTlaMFkxITAfBgNVBAsTGERv\n" +
            "bWFpbiBDb250cm9sIFZhbGlkYXRlZDEdMBsGA1UECxMUUG9zaXRpdmVTU0wgV2ls\n" +
            "ZGNhcmQxFTATBgNVBAMMDCouYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggEPADCCAQoCggEBAMIE7PiM7gTCs9hQ1XBYzJMY61yoaEmwIrX5lZ6xKyx2PmzA\n" +
            "S2BMTOqytMAPgLaw+XLJhgL5XEFdEyt/ccRLvOmULlA3pmccYYz2QULFRtMWhyef\n" +
            "dOsKnRFSJiFzbIRMeVXk0WvoBj1IFVKtsyjbqv9u/2CVSndrOfEk0TG23U3AxPxT\n" +
            "uW1CrbV8/q71FdIzSOciccfCFHpsKOo3St/qbLVytH5aohbcabFXRNsKEqveww9H\n" +
            "dFxBIuGa+RuT5q0iBikusbpJHAwnnqP7i/dAcgCskgjZjFeEU4EFy+b+a1SYQCeF\n" +
            "xxC7c3DvaRhBB0VVfPlkPz0sw6l865MaTIbRyoUCAwEAAaOCAdUwggHRMB8GA1Ud\n" +
            "IwQYMBaAFJCvajqUWgvYkOoSVnPfQ7Q6KNrnMB0GA1UdDgQWBBSd7sF7gQs6R2lx\n" +
            "GH0RN5O8pRs/+zAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUE\n" +
            "FjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwTwYDVR0gBEgwRjA6BgsrBgEEAbIxAQIC\n" +
            "BzArMCkGCCsGAQUFBwIBFh1odHRwczovL3NlY3VyZS5jb21vZG8uY29tL0NQUzAI\n" +
            "BgZngQwBAgEwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDovL2NybC5jb21vZG9jYS5j\n" +
            "b20vQ09NT0RPUlNBRG9tYWluVmFsaWRhdGlvblNlY3VyZVNlcnZlckNBLmNybDCB\n" +
            "hQYIKwYBBQUHAQEEeTB3ME8GCCsGAQUFBzAChkNodHRwOi8vY3J0LmNvbW9kb2Nh\n" +
            "LmNvbS9DT01PRE9SU0FEb21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3J0\n" +
            "MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wIwYDVR0RBBww\n" +
            "GoIMKi5iYWRzc2wuY29tggpiYWRzc2wuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQB1\n" +
            "SIOInFUkNzAH6yZoyHkcXK6aApq1UnVErKntWWXQxkcmBI1XiRYucRhImGgc9jH1\n" +
            "JkvogUSx/1xlPXhUlMOGnUiW6DKv4Y+UR743jMPtTZe7xio3cgE6j4KkNETExPhQ\n" +
            "JEieGfDs4cYTRCa2ZeFiSYek9NjEOTx9QsikKlQFoNwK+CsilJN4Tmo2G9Ln6a6E\n" +
            "7RMdofeig4EDTJ4h+7+oMP7rAGixf7pd4l3/QR/W9aZciu+BgMjxUgAXndGWGn1e\n" +
            "0oOzgsI9RoOlHrQ2NTjEei7fC6GYY1gLHtBtgx/xck0JrJYaC+X2NEyrvLyZW4JZ\n" +
            "5mzT25jgzpU7z04Xw+46\n" +
            "-----END CERTIFICATE-----\n";
    private static final String INTERMEDIATE_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGCDCCA/CgAwIBAgIQKy5u6tl1NmwUim7bo3yMBzANBgkqhkiG9w0BAQwFADCB\n" +
            "hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n" +
            "A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV\n" +
            "BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMjEy\n" +
            "MDAwMDAwWhcNMjkwMjExMjM1OTU5WjCBkDELMAkGA1UEBhMCR0IxGzAZBgNVBAgT\n" +
            "EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR\n" +
            "Q09NT0RPIENBIExpbWl0ZWQxNjA0BgNVBAMTLUNPTU9ETyBSU0EgRG9tYWluIFZh\n" +
            "bGlkYXRpb24gU2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
            "ADCCAQoCggEBAI7CAhnhoFmk6zg1jSz9AdDTScBkxwtiBUUWOqigwAwCfx3M28Sh\n" +
            "bXcDow+G+eMGnD4LgYqbSRutA776S9uMIO3Vzl5ljj4Nr0zCsLdFXlIvNN5IJGS0\n" +
            "Qa4Al/e+Z96e0HqnU4A7fK31llVvl0cKfIWLIpeNs4TgllfQcBhglo/uLQeTnaG6\n" +
            "ytHNe+nEKpooIZFNb5JPJaXyejXdJtxGpdCsWTWM/06RQ1A/WZMebFEh7lgUq/51\n" +
            "UHg+TLAchhP6a5i84DuUHoVS3AOTJBhuyydRReZw3iVDpA3hSqXttn7IzW3uLh0n\n" +
            "c13cRTCAquOyQQuvvUSH2rnlG51/ruWFgqUCAwEAAaOCAWUwggFhMB8GA1UdIwQY\n" +
            "MBaAFLuvfgI9+qbxPISOre44mOzZMjLUMB0GA1UdDgQWBBSQr2o6lFoL2JDqElZz\n" +
            "30O0Oija5zAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV\n" +
            "HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgG\n" +
            "BmeBDAECATBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vY3JsLmNvbW9kb2NhLmNv\n" +
            "bS9DT01PRE9SU0FDZXJ0aWZpY2F0aW9uQXV0aG9yaXR5LmNybDBxBggrBgEFBQcB\n" +
            "AQRlMGMwOwYIKwYBBQUHMAKGL2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9E\n" +
            "T1JTQUFkZFRydXN0Q0EuY3J0MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21v\n" +
            "ZG9jYS5jb20wDQYJKoZIhvcNAQEMBQADggIBAE4rdk+SHGI2ibp3wScF9BzWRJ2p\n" +
            "mj6q1WZmAT7qSeaiNbz69t2Vjpk1mA42GHWx3d1Qcnyu3HeIzg/3kCDKo2cuH1Z/\n" +
            "e+FE6kKVxF0NAVBGFfKBiVlsit2M8RKhjTpCipj4SzR7JzsItG8kO3KdY3RYPBps\n" +
            "P0/HEZrIqPW1N+8QRcZs2eBelSaz662jue5/DJpmNXMyYE7l3YphLG5SEXdoltMY\n" +
            "dVEVABt0iN3hxzgEQyjpFv3ZBdRdRydg1vs4O2xyopT4Qhrf7W8GjEXCBgCq5Ojc\n" +
            "2bXhc3js9iPc0d1sjhqPpepUfJa3w/5Vjo1JXvxku88+vZbrac2/4EjxYoIQ5QxG\n" +
            "V/Iz2tDIY+3GH5QFlkoakdH368+PUq4NCNk+qKBR6cGHdNXJ93SrLlP7u3r7l+L4\n" +
            "HyaPs9Kg4DdbKDsx5Q5XLVq4rXmsXiBmGqW5prU5wfWYQ//u+aen/e7KJD2AFsQX\n" +
            "j4rBYKEMrltDR5FL1ZoXX/nUh8HCjLfn4g8wGTeGrODcQgPmlKidrv0PJFGUzpII\n" +
            "0fxQ8ANAe4hZ7Q7drNJ3gjTcBpUC2JD5Leo31Rpg0Gcg19hCC0Wvgmje3WYkN5Ap\n" +
            "lBlGGSW4gNfL1IYoakRwJiNiqZ+Gb7+6kHDSVneFeO/qJakXzlByjAA6quPbYzSf\n" +
            "+AZxAeKCINT+b72x\n" +
            "-----END CERTIFICATE-----\n";

    private static final String ROOT_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIF2DCCA8CgAwIBAgIQTKr5yttjb+Af907YWwOGnTANBgkqhkiG9w0BAQwFADCB\n" +
            "hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G\n" +
            "A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV\n" +
            "BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMTE5\n" +
            "MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT\n" +
            "EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR\n" +
            "Q09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNh\n" +
            "dGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCR\n" +
            "6FSS0gpWsawNJN3Fz0RndJkrN6N9I3AAcbxT38T6KhKPS38QVr2fcHK3YX/JSw8X\n" +
            "pz3jsARh7v8Rl8f0hj4K+j5c+ZPmNHrZFGvnnLOFoIJ6dq9xkNfs/Q36nGz637CC\n" +
            "9BR++b7Epi9Pf5l/tfxnQ3K9DADWietrLNPtj5gcFKt+5eNu/Nio5JIk2kNrYrhV\n" +
            "/erBvGy2i/MOjZrkm2xpmfh4SDBF1a3hDTxFYPwyllEnvGfDyi62a+pGx8cgoLEf\n" +
            "Zd5ICLqkTqnyg0Y3hOvozIFIQ2dOciqbXL1MGyiKXCJ7tKuY2e7gUYPDCUZObT6Z\n" +
            "+pUX2nwzV0E8jVHtC7ZcryxjGt9XyD+86V3Em69FmeKjWiS0uqlWPc9vqv9JWL7w\n" +
            "qP/0uK3pN/u6uPQLOvnoQ0IeidiEyxPx2bvhiWC4jChWrBQdnArncevPDt09qZah\n" +
            "SL0896+1DSJMwBGB7FY79tOi4lu3sgQiUpWAk2nojkxl8ZEDLXB0AuqLZxUpaVIC\n" +
            "u9ffUGpVRr+goyhhf3DQw6KqLCGqR84onAZFdr+CGCe01a60y1Dma/RMhnEw6abf\n" +
            "Fobg2P9A3fvQQoh/ozM6LlweQRGBY84YcWsr7KaKtzFcOmpH4MN5WdYgGq/yapiq\n" +
            "crxXStJLnbsQ/LBMQeXtHT1eKJ2czL+zUdqnR+WEUwIDAQABo0IwQDAdBgNVHQ4E\n" +
            "FgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB\n" +
            "/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAArx1UaEt65Ru2yyTUEUAJNMnMvl\n" +
            "wFTPoCWOAvn9sKIN9SCYPBMtrFaisNZ+EZLpLrqeLppysb0ZRGxhNaKatBYSaVqM\n" +
            "4dc+pBroLwP0rmEdEBsqpIt6xf4FpuHA1sj+nq6PK7o9mfjYcwlYRm6mnPTXJ9OV\n" +
            "2jeDchzTc+CiR5kDOF3VSXkAKRzH7JsgHAckaVd4sjn8OoSgtZx8jb8uk2Intzna\n" +
            "FxiuvTwJaP+EmzzV1gsD41eeFPfR60/IvYcjt7ZJQ3mFXLrrkguhxuhoqEwWsRqZ\n" +
            "CuhTLJK7oQkYdQxlqHvLI7cawiiFwxv/0Cti76R7CZGYZ4wUAc1oBmpjIXUDgIiK\n" +
            "boHGhfKppC3n9KUkEEeDys30jXlYsQab5xoq2Z0B15R97QNKyvDb6KkBPvVWmcke\n" +
            "jkk9u+UJueBPSZI9FoJAzMxZxuY67RIuaTxslbH9qh17f4a+Hg4yRvv7E491f0yL\n" +
            "S0Zj/gA0QHDBw7mh3aZw4gSzQbzpgJHqZJx64SIDqZxubw5lT2yHh17zbqD5daWb\n" +
            "QOhTsiedSrnAdyGN/4fy3ryM7xfft0kL0fJuMAsaDk527RH89elWsn2/x20Kk4yl\n" +
            "0MC2Hb46TpSi125sC8KKfPog88Tk5c0NqMuRkrF8hey1FGlmDoLnzc7ILaZRfyHB\n" +
            "NVOFBkpdn627G190\n" +
            "-----END CERTIFICATE-----\n";


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

        SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(buildTrustStore(loadTrustedCertificates()), null)
                //(chain, authType) -> {
                //    System.out.println("isTrusted: authType: " + authType);
                //    System.out.println("chain: " + Arrays.toString(chain));
                //    return true;
                //})
                .build();

        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext,
                new String[]{"TLSv1.2"}, null, (hostname, sslSession) -> {
            System.out.println("verify hostname: " + hostname);
            return SSLConnectionSocketFactory.getDefaultHostnameVerifier().verify(hostname, sslSession);
        });

        HttpClientBuilder httpClientBuilder = HttpClients.custom()
            .setMaxConnTotal(maxConnTotal)
            .setMaxConnPerRoute(maxConnPerRoute)
            .setDefaultRequestConfig(requestConfig)
            .setSSLSocketFactory(sslsf);

        httpClient = httpClientBuilder.build();
    }

    private List<X509Certificate> loadTrustedCertificates() throws CertificateException {
        List<X509Certificate> certs = new ArrayList<>();
        //certs.add(CertificateReader.readFromPem(ENTITY_CERT));
        //certs.add(CertificateReader.readFromPem(INTERMEDIATE_CERT));
        certs.add(CertificateReader.readFromPem(ROOT_CERT));
        certs.add(CertificateReader.readFromPem(SOME_CERT));
        return certs;
    }

    private KeyStore buildTrustStore(List<X509Certificate> certificates) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            for (X509Certificate cert : certificates) {
                ks.setCertificateEntry(cert.getSerialNumber().toString(), cert);
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
        return ks;
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
