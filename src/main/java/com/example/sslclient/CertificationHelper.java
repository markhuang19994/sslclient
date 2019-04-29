package com.example.sslclient;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

class CertificationHelper {

    public SSLSocketFactory setOneWayCertificatesSocketFactory(String sslProtocol, InputStream... certificates) {
        try {
            InitTrustManagerFactoryReturn initTrustManagerFactoryReturn = initTrustManagerFactory(sslProtocol, certificates);
            TrustManagerFactory trustManagerFactory = initTrustManagerFactoryReturn.trustManagerFactory;
            SSLContext sslContext = initTrustManagerFactoryReturn.sslContext;
            sslContext.init(
                    null,
                    trustManagerFactory.getTrustManagers(),
                    new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Can't init on way ssl certificate: " + e.getMessage());
        }
    }

    public SSLSocketFactory getNoCertificateValidationSocketFactory(String sslProtocol) throws Exception {
        TrustManager[] tm = new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        SSLContext sslContext = SSLContext.getInstance(sslProtocol, "SunJSSE");
        sslContext.init(null, tm, new SecureRandom());
        return sslContext.getSocketFactory();
    }


    public SSLSocketFactory setTwoWayCertificates(String sslProtocol, InputStream clientCertificate, InputStream... certificates) {
        try {
            InitTrustManagerFactoryReturn initTrustManagerFactoryReturn = initTrustManagerFactory(sslProtocol, certificates);
            TrustManagerFactory trustManagerFactory = initTrustManagerFactoryReturn.trustManagerFactory;
            SSLContext sslContext = initTrustManagerFactoryReturn.sslContext;

            //初始化keystore
            KeyStore clientKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            clientKeyStore.load(clientCertificate, "p@ssw0rd".toCharArray());

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(clientKeyStore, "p@ssw0rd".toCharArray());

            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
    }

    private InitTrustManagerFactoryReturn initTrustManagerFactory(String sslProtocol, InputStream... certificates)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        int index = 0;
        for (InputStream certificate : certificates) {
            String certificateAlias = Integer.toString(index++);
            keyStore.setCertificateEntry(certificateAlias, certificateFactory.generateCertificate(certificate));

            try {
                if (certificate != null)
                    certificate.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        SSLContext sslContext = SSLContext.getInstance(sslProtocol);
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.
                getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        return new InitTrustManagerFactoryReturn(trustManagerFactory, sslContext);
    }

    private class InitTrustManagerFactoryReturn {
        private TrustManagerFactory trustManagerFactory;
        private SSLContext sslContext;

        private InitTrustManagerFactoryReturn(TrustManagerFactory trustManagerFactory, SSLContext sslContext) {
            this.trustManagerFactory = trustManagerFactory;
            this.sslContext = sslContext;
        }
    }
}
