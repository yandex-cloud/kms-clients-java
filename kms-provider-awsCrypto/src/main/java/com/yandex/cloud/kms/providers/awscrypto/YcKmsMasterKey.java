package com.yandex.cloud.kms.providers.awscrypto;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.google.protobuf.ByteString;
import com.yandex.cloud.kms.providers.awscrypto.config.RetryConfig;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;
import org.apache.commons.lang3.NotImplementedException;
import yandex.cloud.api.kms.v1.SymmetricKeyOuterClass;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.yandex.cloud.kms.providers.awscrypto.util.RetryUtils.createRetryPolicy;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.*;
import static yandex.cloud.api.kms.v1.SymmetricKeyOuterClass.SymmetricAlgorithm;

/**
 * Represents single YC KMS key, can be used to perform encrypt/decrypt operations
 */
public class YcKmsMasterKey extends MasterKey<YcKmsMasterKey> {

    private final SymmetricCryptoServiceBlockingStub kmsCryptoService;
    private final String keyId;
    private RetryPolicy<Object> retryPolicy;

    YcKmsMasterKey(String keyId, SymmetricCryptoServiceBlockingStub kmsCryptoService) {
        this.keyId = keyId;
        this.kmsCryptoService = kmsCryptoService;
    }

    YcKmsMasterKey(String keyId, SymmetricCryptoServiceBlockingStub kmsCryptoService, RetryConfig retryConfig) {
        this(keyId, kmsCryptoService);
        this.retryPolicy = createRetryPolicy(retryConfig);
    }

    @Override
    public String getProviderId() {
        return YcKmsMasterKeyProvider.PROVIDER_NAME;
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    /**
     * Sends generateDataKey request to remote KMS
     * @param awsAlgorithm cryptographic algorithm to create data key for, only data key length is important
     * @param encryptionContext AAD context to be used for data key encryption
     * @return generated data key encrypted on KMS key - both plaintext and ciphertext
     */
    @Override
    public DataKey<YcKmsMasterKey> generateDataKey(CryptoAlgorithm awsAlgorithm, Map<String, String> encryptionContext) {
        SymmetricAlgorithm algorithm = convertAlgorithm(awsAlgorithm);
        GenerateDataKeyRequest request = GenerateDataKeyRequest.newBuilder()
                .setKeyId(this.keyId)
                .setDataKeySpec(algorithm)
                .setAadContext(ByteString.copyFrom(convertEncryptionContext(encryptionContext)))
                .setSkipPlaintext(false)
                .build();
        GenerateDataKeyResponse response = doRequest(
                kmsCryptoService::generateDataKey,
                request
        );
        SecretKey secretKey = new SecretKeySpec(response.getDataKeyPlaintext().toByteArray(),
                awsAlgorithm.getDataKeyAlgo());
        return new DataKey<>(secretKey, response.getDataKeyCiphertext().toByteArray(),
                keyId.getBytes(StandardCharsets.UTF_8), this);
    }

    /**
     * Encrypts data key with remote KMS key
     * @param algorithm ignored; remote KMS key algorithm will really be used for encryption
     * @param encryptionContext AAD context to be used for encryption
     * @param dataKey data key to be encrypted
     * @return data key encrypted with KMS key
     */
    @Override
    public DataKey<YcKmsMasterKey> encryptDataKey(CryptoAlgorithm algorithm, Map<String, String> encryptionContext,
                                                  DataKey<?> dataKey) {
        // algorithm param is here only for compatibility reasons and is currently ignored
        SymmetricEncryptRequest request = SymmetricEncryptRequest.newBuilder()
                .setKeyId(this.keyId)
                .setPlaintext(ByteString.copyFrom(dataKey.getKey().getEncoded()))
                .setAadContext(ByteString.copyFrom(convertEncryptionContext(encryptionContext)))
                .build();

        SymmetricEncryptResponse response = doRequest(
                kmsCryptoService::encrypt,
                request
        );
        return new DataKey<>(dataKey.getKey(), response.getCiphertext().toByteArray(),
                keyId.getBytes(StandardCharsets.UTF_8), this);

    }

    /**
     * Decrypts encrypted data key with KMS key
     * @param algorithm cryptographic algorithm to be set in returned data key metadata
     * @param encryptedDataKeys collection of encrypted data keys to try
     * @param encryptionContext AAD context to be used for decryption
     * @return the first data key from the supplied collection that was decrypted successfully
     */
    @Override
    public DataKey<YcKmsMasterKey> decryptDataKey(CryptoAlgorithm algorithm, Collection<? extends EncryptedDataKey> encryptedDataKeys, Map<String, String> encryptionContext) {
        for (EncryptedDataKey encryptedKey : encryptedDataKeys) {
            SymmetricDecryptRequest request = SymmetricDecryptRequest.newBuilder()
                    .setKeyId(this.keyId)
                    .setCiphertext(ByteString.copyFrom(encryptedKey.getEncryptedDataKey()))
                    .setAadContext(ByteString.copyFrom(convertEncryptionContext(encryptionContext)))
                    .build();

            SymmetricDecryptResponse response;
            try {
                response = doRequest(
                        kmsCryptoService::decrypt,
                        request);
                SecretKey secretKey = new SecretKeySpec(response.getPlaintext().toByteArray(),
                        algorithm.getDataKeyAlgo());
                return new DataKey<>(secretKey, encryptedKey.getEncryptedDataKey(),
                        keyId.getBytes(StandardCharsets.UTF_8), this);
            } catch (RuntimeException ex) {
                // let's try another encrypted key
            }
        }
        return null; // unable to decrypt any of given keys
    }

    private static SymmetricKeyOuterClass.SymmetricAlgorithm convertAlgorithm(CryptoAlgorithm algorithm) {
        // we care only about data key length, all other algorithm details are redundant here
        switch (algorithm) {
            case ALG_AES_128_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256:
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256:
                return SymmetricAlgorithm.AES_128;
            case ALG_AES_192_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256:
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
                return SymmetricAlgorithm.AES_192;
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256:
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384:
            case ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY:
            case ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384:
                return SymmetricAlgorithm.AES_256;
            default:
                throw new NotImplementedException(
                        String.format("Algorithm %s not supported by YC KMS", algorithm.name()));
        }
    }

    private static byte[] convertEncryptionContext(Map<String, String> context) {
        if (context == null) {
            return new byte[0];
        }
        return context.entrySet().stream()
                .map(entry -> String.format("%s:%s", entry.getKey(), entry.getValue()))
                .sorted()
                .collect(Collectors.joining(","))
                .getBytes(StandardCharsets.UTF_8);
    }

    private <REQ, RES> RES doRequest(Function<REQ, RES> function, REQ request) {
        return Failsafe.with(retryPolicy)
                .get(context -> function.apply(request));
    }
}