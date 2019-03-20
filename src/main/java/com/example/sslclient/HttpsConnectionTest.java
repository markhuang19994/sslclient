package com.example.sslclient;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class HttpsConnectionTest {

    public static void main(String[] args) throws Exception {
        HttpsConnectionTest httpsConnectionTest = new HttpsConnectionTest();
        SSLSocketFactory ssf = httpsConnectionTest.getOneWayVerificationSocketFactory();

        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://Andy:8487/index").openConnection();
        connection.setSSLSocketFactory(ssf);
        InputStream ips = connection.getInputStream();
        InputStreamReader isr = new InputStreamReader(ips);
        BufferedReader br = new BufferedReader(isr);

        System.out.println(br.readLine());
    }

    private void withoutHostNameVerifier(){
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }

    private SSLSocketFactory getNoVerificationSocketFactory() throws Exception {
        TrustManager[] tm = getDefaultTrustAllManager();
        SSLContext sslContext = SSLContext.getInstance("TLS", "SunJSSE");
        sslContext.init(null, tm, new java.security.SecureRandom());
        return sslContext.getSocketFactory();
    }

    private SSLSocketFactory getOneWayVerificationSocketFactory() throws Exception {
        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(new FileInputStream("/home/markhuang/桌面/ssl/keystore.p12"), "p@ssw0rd".toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);
        TrustManager[] tm = tmf.getTrustManagers();
        HttpsConnectionTest httpsConnectionTest = new HttpsConnectionTest();
        SSLContext sslContext = SSLContext.getInstance("TLS", "SunJSSE");
        sslContext.init(null, tm, new java.security.SecureRandom());
        return sslContext.getSocketFactory();
    }

    private TrustManager[] getDefaultTrustAllManager() {
        return new TrustManager[]{new X509TrustManager() {
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
    }


}
