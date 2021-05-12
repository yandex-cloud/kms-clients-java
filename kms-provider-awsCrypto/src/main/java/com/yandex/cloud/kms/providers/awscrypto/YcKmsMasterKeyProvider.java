package com.yandex.cloud.kms.providers.awscrypto;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.MasterKeyProvider;
import com.amazonaws.encryptionsdk.MasterKeyRequest;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import yandex.cloud.api.kms.v1.SymmetricCryptoServiceGrpc;
import yandex.cloud.sdk.ServiceFactory;
import yandex.cloud.sdk.auth.Auth;
import yandex.cloud.sdk.auth.provider.CredentialProvider;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Provider for constructing YcKmsMasterKey objects.
 * Holds endpoint and credentials information for YC KMS installation to be used.
 */
public class YcKmsMasterKeyProvider extends MasterKeyProvider<YcKmsMasterKey> {
    static final String PROVIDER_NAME = "yc-kms";

    private String endpoint;
    private CredentialProvider credentialProvider;
    private Collection<String> keyIds;

    public YcKmsMasterKeyProvider() {
    }

    public YcKmsMasterKeyProvider(String endpoint, CredentialProvider credentialProvider, Collection<String> keyIds) {
        this.endpoint = endpoint;
        this.credentialProvider = credentialProvider;
        this.keyIds = Collections.unmodifiableCollection(keyIds);
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

        if (credentialProvider == null) {
            throw new IllegalStateException("credentials was not provided for KMS client");
        }
        ServiceFactory.ServiceFactoryBuilder serviceFactoryBuilder = ServiceFactory.builder()
                .credentialProvider(credentialProvider)
                .requestTimeout(Duration.ofSeconds(10));

        if (endpoint != null) {
            serviceFactoryBuilder = serviceFactoryBuilder.endpoint(endpoint);
        }
        ServiceFactory factory = serviceFactoryBuilder.build();
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
     * Specifies static OAuth token as a credentials
     *
     * @param credentialPath file path to OAuth token
     * @return instance of YcKmsMasterKeyProvider with injected credentials
     */
    public YcKmsMasterKeyProvider withCredentials(String credentialPath) {
        this.credentialProvider = Auth.oauthTokenBuilder().fromFile(Paths.get(credentialPath)).build();
        return this;
    }

    /**
     * Specifies dynamic credentials provider for the KMS client
     *
     * @param credentialProvider function that returns credentials
     * @return instance of YcKmsMasterKeyProvider with injected credentials
     */
    public YcKmsMasterKeyProvider withCredentials(CredentialProvider credentialProvider) {
        this.credentialProvider = credentialProvider;
        return this;
    }

    /**
     * Specifies keys for the KMS client
     *
     * @param keyIds collection of YC KMS key ids to be used
     * @return instance of YcKmsMasterKeyProvider with injected YC KMS keys
     */
    public YcKmsMasterKeyProvider withKeyIds(Collection<String> keyIds) {
        this.keyIds = Collections.unmodifiableCollection(keyIds);
        return this;
    }

    /**
     * Specifies single key for the KMS client
     *
     * @param keyId single YC KMS key id to be used
     * @return instance of YcKmsMasterKeyProvider with injected YC KMS key
     */
    public YcKmsMasterKeyProvider withKeyId(String keyId) {
        this.keyIds = Collections.singleton(keyId);
        return this;
    }

    /**
     * Specifies endpoint for the KMS client (optional)
     *
     * @param endpoint
     * @return instance of KmsClient with injected endpoint
     */
    public YcKmsMasterKeyProvider withEndpoint(String endpoint) {
        this.endpoint = endpoint;
        return this;
    }

    /**
     * Decrypts encrypted data key from the given collection of keys with KMS key
     *
     * @param algorithm         cryptographic algorithm to be set in the returned data key metadata
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
