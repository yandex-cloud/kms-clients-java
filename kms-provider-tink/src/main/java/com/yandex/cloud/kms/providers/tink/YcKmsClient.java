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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.function.Supplier;

public class YcKmsClient implements KmsClient {
    /** The prefix of all keys stored in Yandex Cloud KMS. */
    public static final String PREFIX = "yc-kms://";

    private Supplier<Credentials> credentialsSupplier;

    public YcKmsClient() {
    }

    public YcKmsClient(Supplier<Credentials> credentialsSupplier) {
        this.credentialsSupplier = credentialsSupplier;
    }

    @Override
    public boolean doesSupport(String keyUri) {
        return StringUtils.isNotBlank(keyUri) && keyUri.toLowerCase().startsWith(PREFIX);
    }

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

    public KmsClient withCredentials(Supplier<Credentials> credentialsSupplier) {
        this.credentialsSupplier = credentialsSupplier;
        return this;
    }

    @Override
    public KmsClient withDefaultCredentials() {
        throw new NotImplementedException("withDefaultCredentials() not implemented");
    }

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
            throw new IllegalArgumentException("Key URI doesn't start with prefix " + PREFIX);
        }
    }
}
