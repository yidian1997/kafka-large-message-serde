package com.bakdata.kafka;

import software.amazon.awssdk.http.TlsTrustManagersProvider;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;

public class DefaultTlsTrustManagersProvider implements TlsTrustManagersProvider {

    @Override
    public TrustManager[] trustManagers() {
        try {
            TrustManagerFactory trustManagerFactory =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);

            return trustManagerFactory.getTrustManagers();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load default trust store", e);
        }
    }
}

