package com.yandex.cloud.kms.providers.tink;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.yandex.cloud.kms.providers.tink.config.RetryConfig;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import yandex.cloud.api.kms.v1.SymmetricCryptoServiceGrpc;
import yandex.cloud.sdk.ChannelFactory;
import yandex.cloud.sdk.ServiceFactory;
import yandex.cloud.sdk.auth.Auth;
import yandex.cloud.sdk.auth.provider.CredentialProvider;

import java.nio.file.Paths;
import java.time.Duration;

/**
 * Holds YC KMS endpoint and credentials information; allows creating Aead primitive linked to specific YC KMS Key
 */
public class YcKmsClient implements KmsClient {
    /**
     * The prefix of all keys stored in Yandex Cloud KMS.
     */
    public static final String PREFIX = "yc-kms://";

    private CredentialProvider credentialProvider;
    private String endpoint;
    private ChannelFactory channelFactory;
    private RetryConfig retryConfig;

    public YcKmsClient() {
    }

    public YcKmsClient(RetryConfig retryConfig) {
        this.retryConfig = retryConfig;
    }

    /**
     * Constructs KMS client using given lazy credentials provider
     *
     * @param credentialProvider function that returns credentials
     */
    public YcKmsClient(CredentialProvider credentialProvider) {
        this.credentialProvider = credentialProvider;
    }

    public YcKmsClient(CredentialProvider credentialProvider, RetryConfig retryConfig) {
        this(credentialProvider);
        this.retryConfig = retryConfig;
    }

    /**
     * Checks if given key URI supported by this provider; only YC KMS key URIs are supported
     *
     * @param keyUri key URI
     * @return true if URI is supported
     */
    @Override
    public boolean doesSupport(String keyUri) {
        return StringUtils.isNotBlank(keyUri) && keyUri.toLowerCase().startsWith(PREFIX);
    }

    /**
     * Specifies static OAuth token as a credentials
     *
     * @param credentialPath file path to OAuth token
     * @return instance of KmsClient with injected credentials
     */
    @Override
    public KmsClient withCredentials(String credentialPath) {
        this.credentialProvider = Auth.oauthTokenBuilder().fromFile(Paths.get(credentialPath)).build();
        return this;
    }

    /**
     * Specifies dynamic credentials provider for the KMS client
     *
     * @param credentialProvider function that returns credentials
     * @return instance of KmsClient with injected credentials
     */
    public KmsClient withCredentials(CredentialProvider credentialProvider) {
        this.credentialProvider = credentialProvider;
        return this;
    }

    /**
     * Not supported
     */
    @Override
    public KmsClient withDefaultCredentials() {
        throw new NotImplementedException("withDefaultCredentials() not implemented");
    }

    /**
     * Specifies endpoint for the KMS client (optional)
     *
     * @param endpoint
     * @return instance of KmsClient with injected endpoint
     */
    public KmsClient withEndpoint(String endpoint) {
        this.endpoint = endpoint;
        this.channelFactory = null;
        return this;
    }

    /**
     * Specifies channel factory for the KMS client (optional)
     *
     * @param channelFactory
     * @return instance of KmsClient with injected channel factory
     */
    public KmsClient withChannelFactory(ChannelFactory channelFactory) {
        this.channelFactory = channelFactory;
        this.endpoint = null;
        return this;
    }

    /**
     * Constructs Aead primitive for the specified YC KMS key
     *
     * @param keyUri YC KMS key URI
     * @return Aead primitive
     */
    @Override
    public Aead getAead(String keyUri) {
        if (credentialProvider == null) {
            throw new IllegalStateException("credentials was not provided for KMS client");
        }

        ServiceFactory.ServiceFactoryBuilder factoryBuilder = ServiceFactory.builder()
                .credentialProvider(credentialProvider)
                .requestTimeout(Duration.ofSeconds(10));

        if (channelFactory != null) {
            factoryBuilder.channelFactory(channelFactory);
        }
        if (endpoint != null) {
            factoryBuilder.endpoint(endpoint);
        }

        ServiceFactory factory = factoryBuilder.build();
        SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub cryptoService =
                factory.create(
                        SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub.class,
                        SymmetricCryptoServiceGrpc::newBlockingStub);

        return new YcKmsAead(cryptoService, trimPrefix(keyUri), retryConfig);
    }

    private static String trimPrefix(String keyUri) {
        if (keyUri.startsWith(PREFIX)) {
            return keyUri.substring(PREFIX.length());
        } else {
            throw new IllegalArgumentException(String.format("Key URI doesn't start with prefix %s", PREFIX));
        }
    }
}
