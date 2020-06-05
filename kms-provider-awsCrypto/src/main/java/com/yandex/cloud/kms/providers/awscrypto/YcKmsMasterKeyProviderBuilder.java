package com.yandex.cloud.kms.providers.awscrypto;

import yandex.cloud.sdk.auth.Credentials;

import java.util.Collections;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Builder for constructing YcKmsMasterKeyProvider objects
 */
public class YcKmsMasterKeyProviderBuilder {
    private String host;
    private int port;
    private Supplier<Credentials> credentialsSupplier;
    private Set<String> keyIds = Collections.emptySet();

    /**
     * @param host host part of YC KMS endpoint
     * @return self
     */
    public YcKmsMasterKeyProviderBuilder setHost(String host) {
        this.host = host;
        return this;
    }

    /**
     * @param port port part of YC KMS endpoint
     * @return self
     */
    public YcKmsMasterKeyProviderBuilder setPort(int port) {
        this.port = port;
        return this;
    }

    /**
     * @param credentialsSupplier function that supplies YC KMS credentials
     * @return self
     */
    public YcKmsMasterKeyProviderBuilder setCredentialsSupplier(Supplier<Credentials> credentialsSupplier) {
        this.credentialsSupplier = credentialsSupplier;
        return this;
    }

    /**
     * @param keyIds collection of YC KMS key ids to be used
     * @return self
     */
    public YcKmsMasterKeyProviderBuilder setKeyIds(Set<String> keyIds) {
        this.keyIds = keyIds;
        return this;
    }

    /**
     * @param keyId single YC KMS key id to be used
     * @return self
     */
    public YcKmsMasterKeyProviderBuilder setKeyId(String keyId) {
        this.keyIds = Collections.singleton(keyId);
        return this;
    }

    /**
     * @return constructed master key provider object
     */
    public YcKmsMasterKeyProvider build() {
        return new YcKmsMasterKeyProvider(host, port, credentialsSupplier, keyIds);
    }
}
