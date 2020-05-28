package com.yandex.cloud.kms.providers.awscrypto;

import yandex.cloud.sdk.auth.Credentials;

import java.util.Collections;
import java.util.Set;
import java.util.function.Supplier;

public class YcKmsMasterKeyProviderBuilder {
    private String host;
    private int port;
    private Supplier<Credentials> credentialsSupplier;
    private Set<String> keyIds = Collections.emptySet();

    public YcKmsMasterKeyProviderBuilder setHost(String host) {
        this.host = host;
        return this;
    }

    public YcKmsMasterKeyProviderBuilder setPort(int port) {
        this.port = port;
        return this;
    }

    public YcKmsMasterKeyProviderBuilder setCredentialsSupplier(Supplier<Credentials> credentialsSupplier) {
        this.credentialsSupplier = credentialsSupplier;
        return this;
    }

    public YcKmsMasterKeyProviderBuilder setKeyIds(Set<String> keyIds) {
        this.keyIds = keyIds;
        return this;
    }

    public YcKmsMasterKeyProviderBuilder setKeyId(String keyId) {
        this.keyIds = Collections.singleton(keyId);
        return this;
    }


    public YcKmsMasterKeyProvider build() {
        return new YcKmsMasterKeyProvider(host, port, credentialsSupplier, keyIds);
    }
}
