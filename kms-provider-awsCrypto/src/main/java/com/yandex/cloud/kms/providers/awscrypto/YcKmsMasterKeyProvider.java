package com.yandex.cloud.kms.providers.awscrypto;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import yandex.cloud.api.kms.v1.SymmetricCryptoServiceGrpc;
import yandex.cloud.sdk.ServiceFactory;
import yandex.cloud.sdk.ServiceFactoryConfig;
import yandex.cloud.sdk.auth.Credentials;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class YcKmsMasterKeyProvider extends MasterKeyProvider<YcKmsMasterKey> {
    static final String PROVIDER_NAME = "yc-kms";

    private final String host;
    private final int port;
    private final Supplier<Credentials> credentialsSupplier;
    private final Set<String> keyIds;

    public static YcKmsMasterKeyProviderBuilder builder() {
        return new YcKmsMasterKeyProviderBuilder();
    }

    YcKmsMasterKeyProvider(String host, int port, Supplier<Credentials> credentialsSupplier, Set<String> keyIds) {
        this.host = host;
        this.port = port;
        this.credentialsSupplier = credentialsSupplier;
        this.keyIds = Collections.unmodifiableSet(keyIds);
    }

    @Override
    public String getDefaultProviderId() {
        return PROVIDER_NAME;
    }

    @Override
    public YcKmsMasterKey getMasterKey(String provider, String keyId)
            throws UnsupportedProviderException, NoSuchMasterKeyException {

        validateProvider(provider);

        if (credentialsSupplier == null) {
            throw new IllegalStateException("credentials was not provided for KMS client");
        }
        ServiceFactoryConfig.ServiceFactoryConfigBuilder configBuilder = ServiceFactoryConfig.builder()
                .credentials(credentialsSupplier.get())
                .requestTimeout(Duration.ofSeconds(10));
        if (host != null) {
            configBuilder = configBuilder.endpoint(host).port(port);
        }
        ServiceFactory factory = new ServiceFactory(configBuilder.build());
        SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub cryptoService =
                factory.create(
                        SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub.class,
                        SymmetricCryptoServiceGrpc::newBlockingStub);


        return new YcKmsMasterKey(keyId, cryptoService);
    }

    @Override
    public List<YcKmsMasterKey> getMasterKeysForEncryption(MasterKeyRequest request) {
        return keyIds.stream()
                .map(keyStr -> getMasterKey(PROVIDER_NAME, keyStr))
                .collect(Collectors.toList());
    }

    @Override
    public DataKey<YcKmsMasterKey> decryptDataKey(CryptoAlgorithm algorithm,
                                                  Collection<? extends EncryptedDataKey> encryptedDataKeys,
                                                  Map<String, String> encryptionContext)
            throws AwsCryptoException {

        for (EncryptedDataKey encryptedKey : encryptedDataKeys) {
            String keyId = new String(encryptedKey.getProviderInformation(), StandardCharsets.UTF_8);
            MasterKey<YcKmsMasterKey> key = getMasterKey(PROVIDER_NAME, keyId);
            DataKey<YcKmsMasterKey> decryptedKey = key.decryptDataKey(algorithm, encryptedDataKeys, encryptionContext);
            if (decryptedKey != null) {
                return decryptedKey;
            }
        }
        return null;
    }

    private static void validateProvider(String provider) {
        if (!PROVIDER_NAME.equals(provider)) {
            throw new UnsupportedProviderException(String.format("Provider %s not supported", provider));
        }
    }
}
