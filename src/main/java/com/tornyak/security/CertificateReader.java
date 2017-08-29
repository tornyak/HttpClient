package com.tornyak.security;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by etkvadi on 2017-08-29.
 */
public class CertificateReader {

    private static final String ENDCERT = "-----END CERTIFICATE-----";
    private static final String BEGINCERT = "-----BEGIN CERTIFICATE-----";
    private static final String ENDCERTREGEX = "[-]+END[\\s]{0,1}CERTIFICATE[-]+";
    private static final String BEGINCERTREGEX = "[-]+BEGIN[\\s]{0,1}CERTIFICATE[-]+";

    public static X509Certificate readFromPem(String pemCert) {
        X509Certificate cert = null;
        byte[] DER = pemToDER(getFirstCertificate(pemCert));
        try (InputStream in = new ByteArrayInputStream(DER)) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) certFactory.generateCertificate(in);
        } catch (Exception e) {

        }
        return cert;
    }

    private static byte[] pemToDER(String pemString) {
        String trimmedString = trimHeaders(trimWhiteSpace(pemString));
        if (trimmedString != null && trimmedString.length() > 0) {
            return Base64.decodeBase64(trimmedString);
        }
        return new byte[0];
    }

    private static String trimHeaders(String headerString) {
        if (headerString != null) {
            return headerString.replaceAll(BEGINCERTREGEX, "")
                    .replaceAll(ENDCERTREGEX, "");
        }
        return null;
    }

    private static String getFirstCertificate(String pemCert) {
        if (pemCert != null && pemCert.length() > 0) {
            String[] pemCerts = splitPemCertificates(pemCert);
            return pemCerts[0];
        }
        return null;
    }

    private static String[] splitPemCertificates(String pemString) {
        String[] pemStrings = pemString.split(ENDCERTREGEX);
        for (int n = 0; n < pemStrings.length; n++) {
            pemStrings[n] = pemStrings[n] + ENDCERT;
        }
        return pemStrings;
    }

    private static String trimWhiteSpace(String whiteString) {
        if (whiteString != null) {
            return whiteString.replaceAll("\\s+", "");
        }
        return null;
    }
}
