package com.yandex.cloud.kms.providers.tink;

import com.google.crypto.tink.Aead;
import com.google.protobuf.ByteString;

import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.SymmetricDecryptRequest;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceGrpc.SymmetricCryptoServiceBlockingStub;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.SymmetricDecryptResponse;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.SymmetricEncryptRequest;
import static yandex.cloud.api.kms.v1.SymmetricCryptoServiceOuterClass.SymmetricEncryptResponse;

public class YcKmsAead implements Aead {

    private final SymmetricCryptoServiceBlockingStub cryptoService;
    private final String keyId;

    YcKmsAead(SymmetricCryptoServiceBlockingStub cryptoService, String keyId) {
        this.cryptoService = cryptoService;
        this.keyId = keyId;
    }

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
        SymmetricEncryptRequest request = SymmetricEncryptRequest.newBuilder()
                .setKeyId(this.keyId)
                .setPlaintext(ByteString.copyFrom(plaintext))
                .setAadContext(ByteString.copyFrom(associatedData))
                .build();

        SymmetricEncryptResponse response = cryptoService.encrypt(request);
        return response.getCiphertext().toByteArray();
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] associatedData) {
        SymmetricDecryptRequest request = SymmetricDecryptRequest.newBuilder()
                .setKeyId(this.keyId)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setAadContext(ByteString.copyFrom(associatedData))
                .build();

        SymmetricDecryptResponse response = cryptoService.decrypt(request);
        return response.getPlaintext().toByteArray();
    }
}
