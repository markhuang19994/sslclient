package com.example.sslclient;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 流程：
 *      1.client傳送cer給server驗證
 *      2.client驗證server傳送的cer
 */
public class HttpsConnectionTest {

    public static void main(String[] args) throws Exception {
        HttpsConnectionTest httpsConnectionTest = new HttpsConnectionTest();
        SSLSocketFactory ssf = new CertificationHelper().setTwoWayCertificates(
                "TLSv1.2",
                new FileInputStream("/home/markhuag/Documents/project/source/Tdd/ssl/src/main/resources/keystore.p12"),
                new FileInputStream("/home/markhuag/Desktop/learn/ssl/key/mykey.cer")
        );
        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://localhost:8487/index").openConnection();
        connection.setHostnameVerifier((hostname, session) -> true);
        connection.setSSLSocketFactory(ssf);
        InputStream ips = connection.getInputStream();
        InputStreamReader isr = new InputStreamReader(ips);
        BufferedReader br = new BufferedReader(isr);

        System.out.println(br.readLine());
    }

}

