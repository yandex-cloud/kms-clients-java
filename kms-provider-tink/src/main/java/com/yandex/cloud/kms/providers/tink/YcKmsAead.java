package com.yandex.cloud.kms.providers.tink;

import com.google.crypto.tink.Aead;
import com.google.protobuf.ByteString;
import com.yandex.cloud.kms.providers.tink.config.RetryConfig;
import net.jodah.failsafe.Failsafe;
import net.jodah.failsafe.RetryPolicy;

import java.util.function.Function;

import static com.yandex.cloud.kms.providers.tink.util.RetryUtils.createRetryPolicy;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.*;

/**
 * Represents single YC KMS key; allows to perform encrypt/decrypt operations on this key.
 */
public class YcKmsAead implements Aead {

    private final SymmetricCryptoServiceBlockingStub cryptoService;
    private final String keyId;
    private RetryPolicy<Object> retryPolicy;

    YcKmsAead(SymmetricCryptoServiceBlockingStub cryptoService, String keyId, RetryConfig retryConfig) {
        this.cryptoService = cryptoService;
        this.keyId = keyId;
        this.retryPolicy = createRetryPolicy(retryConfig);
    }

    /**
     * Encrypts given plaintext on this KMS key
     *
     * @param plaintext      plaintext to encrypt
     * @param associatedData ADD context
     * @return encrypted ciphertext
     */
    @Override
    public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
        SymmetricEncryptRequest request = SymmetricEncryptRequest.newBuilder()
                .setKeyId(this.keyId)
                .setPlaintext(ByteString.copyFrom(plaintext))
                .setAadContext(ByteString.copyFrom(associatedData))
                .build();

        SymmetricEncryptResponse response = doRequest(
                cryptoService::encrypt,
                request
        );
        return response.getCiphertext().toByteArray();
    }

    /**
     * Decrypts given ciphertext on this KMS key
     * @param ciphertext ciphertext to decrypt
     * @param associatedData AAD context
     * @return decrypted plaintext
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] associatedData) {
        SymmetricDecryptRequest request = SymmetricDecryptRequest.newBuilder()
                .setKeyId(this.keyId)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setAadContext(ByteString.copyFrom(associatedData))
                .build();

        SymmetricDecryptResponse response = doRequest(
                cryptoService::decrypt,
                request
        );
        return response.getPlaintext().toByteArray();
    }

    private <REQ, RES> RES doRequest(Function<REQ, RES> function, REQ request) {
        return Failsafe.with(retryPolicy)
                .get(context -> function.apply(request));
    }
}