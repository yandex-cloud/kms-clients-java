package com.yandex.cloud.kms.providers.awscrypto;

import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.DataKey;
import com.amazonaws.encryptionsdk.EncryptedDataKey;
import com.amazonaws.encryptionsdk.MasterKey;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.UnsupportedProviderException;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.NotImplementedException;
import yandex.cloud.api.kms.v1.SymmetricKeyOuterClass;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.GenerateDataKeyRequest;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.GenerateDataKeyResponse;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.SymmetricDecryptRequest;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.SymmetricDecryptResponse;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.SymmetricEncryptRequest;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.SymmetricEncryptResponse;
import static yandex.cloud.api.kms.v1.SymmetricKeyOuterClass.SymmetricAlgorithm;

public class YcKmsMasterKey extends MasterKey<YcKmsMasterKey> {

    private final SymmetricCryptoServiceBlockingStub kmsCryptoService;
    private final String keyId;

    YcKmsMasterKey(String keyId, SymmetricCryptoServiceBlockingStub kmsCryptoService) {
        this.keyId = keyId;
        this.kmsCryptoService = kmsCryptoService;
    }

    @Override
    public String getProviderId() {
        return YcKmsMasterKeyProvider.PROVIDER_NAME;
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    @Override
    public DataKey<YcKmsMasterKey> generateDataKey(CryptoAlgorithm awsAlgorithm, Map<String, String> encryptionContext) {
        SymmetricAlgorithm algorithm = convertAlgorithm(awsAlgorithm);
        GenerateDataKeyRequest request = GenerateDataKeyRequest.newBuilder()
                .setKeyId(this.keyId)
                .setDataKeySpec(algorithm)
                .setAadContext(ByteString.copyFrom(encryptionContext == null ? null : convertEncryptionContext(encryptionContext)))
                .setSkipPlaintext(false)
                .build();
        GenerateDataKeyResponse response = kmsCryptoService.generateDataKey(request);
        SecretKey secretKey = new SecretKeySpec(response.getDataKeyPlaintext().toByteArray(),
                awsAlgorithm.getDataKeyAlgo());
        return new DataKey<>(secretKey, response.getDataKeyCiphertext().toByteArray(),
                keyId.getBytes(StandardCharsets.UTF_8), this);
    }

    @Override
    public DataKey<YcKmsMasterKey> encryptDataKey(CryptoAlgorithm algorithm, Map<String, String> encryptionContext,
                                                  DataKey<?> dataKey) {
        // FIXME let's just ignore the algorithm param
        SymmetricEncryptRequest request = SymmetricEncryptRequest.newBuilder()
                .setKeyId(this.keyId)
                .setPlaintext(ByteString.copyFrom(dataKey.getKey().getEncoded()))
                .setAadContext(ByteString.copyFrom(encryptionContext == null ? null : convertEncryptionContext(encryptionContext)))
                .build();

        SymmetricEncryptResponse response = kmsCryptoService.encrypt(request);
        return new DataKey<>(dataKey.getKey(), response.getCiphertext().toByteArray(),
                keyId.getBytes(StandardCharsets.UTF_8), this);

    }

    @Override
    public DataKey<YcKmsMasterKey> decryptDataKey(CryptoAlgorithm algorithm, Collection<? extends EncryptedDataKey> encryptedDataKeys, Map<String, String> encryptionContext) throws UnsupportedProviderException, AwsCryptoException {
        // FIXME let's just ignore algorithm param
        for (EncryptedDataKey encryptedKey : encryptedDataKeys) {
            SymmetricDecryptRequest request = SymmetricDecryptRequest.newBuilder()
                    .setKeyId(this.keyId)
                    .setCiphertext(ByteString.copyFrom(encryptedKey.getEncryptedDataKey()))
                    .setAadContext(ByteString.copyFrom(encryptionContext == null ?
                            null : convertEncryptionContext(encryptionContext)))
                    .build();

            SymmetricDecryptResponse response;
            try {
                response = kmsCryptoService.decrypt(request);
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
        switch (algorithm) {
            case ALG_AES_128_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256: //FIXME
            case ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256: //FIXME
                return SymmetricAlgorithm.AES_128;
            case ALG_AES_192_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256: //FIXME
            case ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384: //FIXME
                return SymmetricAlgorithm.AES_192;
            case ALG_AES_256_GCM_IV12_TAG16_NO_KDF:
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256: //FIXME
            case ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384: //FIXME
                return SymmetricAlgorithm.AES_256;
            default:
                throw new NotImplementedException(String.format("Algorithm %s not supported by YC KMS",
                        algorithm.name()));
        }
    }

    private static byte[] convertEncryptionContext(Map<String, String> context) {
        return context.entrySet().stream()
                .map(entry -> String.format("%s:%s", entry.getKey(), entry.getValue()))
                .sorted()
                .collect(Collectors.joining(","))
                .getBytes(StandardCharsets.UTF_8);
    }
}
