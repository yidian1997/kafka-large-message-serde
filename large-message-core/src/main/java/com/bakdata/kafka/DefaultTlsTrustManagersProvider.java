package com.bakdata.kafka;

import software.amazon.awssdk.http.TlsTrustManagersProvider;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

public class DefaultTlsTrustManagersProvider implements TlsTrustManagersProvider {

    @Override
    public TrustManager[] trustManagers() {
        // Create a trust manager wrapper to simulate adding self-signed CA cert into the default trust store
        X509TrustManager defaultTrustStore = loadDefaultTrustStore();

        X509TrustManager trustManagerWrapper = new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                assert defaultTrustStore != null;
                defaultTrustStore.checkClientTrusted(defaultTrustStore.getAcceptedIssuers(), authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                assert defaultTrustStore != null;
                defaultTrustStore.checkServerTrusted(defaultTrustStore.getAcceptedIssuers(), authType);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                assert defaultTrustStore != null;
                return defaultTrustStore.getAcceptedIssuers();
            }
        };

        return new X509TrustManager[] {trustManagerWrapper};
    }

    private X509TrustManager loadDefaultTrustStore() {
        try {
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);

            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                if (trustManager instanceof X509TrustManager) {
                    return (X509TrustManager) trustManager;
                }
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load default trust store", e);
        }
        return null;
    }
}

