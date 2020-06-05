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

    /**
     * @return provider builder
     */
    public static YcKmsMasterKeyProviderBuilder builder() {
        return new YcKmsMasterKeyProviderBuilder();
    }

    YcKmsMasterKeyProvider(String host, int port, Supplier<Credentials> credentialsSupplier, Set<String> keyIds) {
        this.host = host;
        this.port = port;
        this.credentialsSupplier = credentialsSupplier;
        this.keyIds = Collections.unmodifiableSet(keyIds);
    }

    /**
     * @return id of the provider supported
     */
    @Override
    public String getDefaultProviderId() {
        return PROVIDER_NAME;
    }

    /**
     * Constructs master key object for given provider and keyId
     * @param provider provider id, should be equal to "yc-kms"
     * @param keyId key id to be used
     * @return constructed master key object
     * @throws UnsupportedProviderException if provider is not equal to "yc-kms"
     */
    @Override
    public YcKmsMasterKey getMasterKey(String provider, String keyId)
            throws UnsupportedProviderException {

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

    /**
     * Bulk method for constructing master key objects
     * @param request bulk request
     * @return collection of created master key objects
     */
    @Override
    public List<YcKmsMasterKey> getMasterKeysForEncryption(MasterKeyRequest request) {
        return keyIds.stream()
                .map(keyStr -> getMasterKey(PROVIDER_NAME, keyStr))
                .collect(Collectors.toList());
    }

    /**
     *
     * @param algorithm cryptographic algorithm to be used for decryption; will be converted to the
     *                  version of algorithm supported by YC KMS
     * @param encryptedDataKeys collection of encrypted data key objects
     * @param encryptionContext AAD context to be used for decryption
     * @return collection of decrypted data keys
     */
    @Override
    public DataKey<YcKmsMasterKey> decryptDataKey(CryptoAlgorithm algorithm,
                                                  Collection<? extends EncryptedDataKey> encryptedDataKeys,
                                                  Map<String, String> encryptionContext)
    {

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
