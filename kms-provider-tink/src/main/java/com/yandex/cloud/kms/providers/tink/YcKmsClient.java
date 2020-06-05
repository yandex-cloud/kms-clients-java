package com.yandex.cloud.kms.providers.tink;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import org.apache.commons.lang3.NotImplementedException;
import org.apache.commons.lang3.StringUtils;
import yandex.cloud.api.kms.v1.SymmetricCryptoServiceGrpc;
import yandex.cloud.sdk.ServiceFactory;
import yandex.cloud.sdk.ServiceFactoryConfig;
import yandex.cloud.sdk.auth.Auth;
import yandex.cloud.sdk.auth.Credentials;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.function.Supplier;

/**
 * Holds YC KMS endpoint and credentials information; allows creating Aead primitive linked to specific YC KMS Key
 */
public class YcKmsClient implements KmsClient {
    /** The prefix of all keys stored in Yandex Cloud KMS. */
    public static final String PREFIX = "yc-kms://";

    private Supplier<Credentials> credentialsSupplier;

    public YcKmsClient() {
    }

    /**
     * Constructs KMS client using given lazy credentials supplier
     * @param credentialsSupplier function that returns credentials
     */
    public YcKmsClient(Supplier<Credentials> credentialsSupplier) {
        this.credentialsSupplier = credentialsSupplier;
    }

    /**
     * Checks if given key URI supported by this provider; only YC KMS key URIs are supported
     * @param keyUri key URI
     * @return true if URI is supported
     */
    @Override
    public boolean doesSupport(String keyUri) {
        return StringUtils.isNotBlank(keyUri) && keyUri.toLowerCase().startsWith(PREFIX);
    }

    /**
     * Specifies static OAuth token as a credentials
     * @param credentialPath file path to OAuth token
     * @return instance of KmsClient with injected credentials
     */
    @Override
    public KmsClient withCredentials(String credentialPath) {
        this.credentialsSupplier = () -> {
            try {
                return Auth.fromFile(Auth::oauthToken, Paths.get(credentialPath));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        };
        return this;
    }

    /**
     * Specifies dynamic credentials provider for the KMS client
     * @param credentialsSupplier function that supplies credentials
     * @return instance of KmsClient with injected credentials
     */
    public KmsClient withCredentials(Supplier<Credentials> credentialsSupplier) {
        this.credentialsSupplier = credentialsSupplier;
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
     * Constructs Aead primitive for the specified YC KMS key
     * @param keyUri YC KMS key URI
     * @return Aead primitive
     */
    @Override
    public Aead getAead(String keyUri) {
        if (credentialsSupplier == null) {
            throw new IllegalStateException("credentials was not provided for KMS client");
        }

        ServiceFactoryConfig config = ServiceFactoryConfig.builder()
                .credentials(credentialsSupplier.get())
                .requestTimeout(Duration.ofSeconds(10))
                .build();

        ServiceFactory factory = new ServiceFactory(config);
        SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub cryptoService =
                factory.create(
                        SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub.class,
                        SymmetricCryptoServiceGrpc::newBlockingStub);

        return new YcKmsAead(cryptoService, trimPrefix(keyUri));
    }

    private static String trimPrefix(String keyUri) {
        if (keyUri.startsWith(PREFIX)) {
            return keyUri.substring(PREFIX.length());
        } else {
            throw new IllegalArgumentException(String.format("Key URI doesn't start with prefix %s", PREFIX));
        }
    }
}
