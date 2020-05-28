package com.yandex.cloud.kms.providers.examples;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.aead.KmsEnvelopeAead;
import com.yandex.cloud.kms.providers.tink.YcKmsClient;
import org.apache.commons.codec.Charsets;
import org.apache.commons.lang3.Validate;
import yandex.cloud.sdk.auth.Auth;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

public class TinkStringExample {
    private static final String YCKMS_OAUTH = "YCKMS_OAUTH";

    public static void main(final String[] args) throws GeneralSecurityException {
        Validate.isTrue(args.length >= 2, "Invalid number of arguments");

        // prepare data
        String keyId = "yc-kms://" + args[0];
        byte[] plaintext = args[1].getBytes(Charsets.UTF_8);
        byte[] context = "Foo: Bar".getBytes(Charsets.UTF_8);

        // register YC KMS provider in tink's registry
        KmsClients.add(new YcKmsClient(() -> Auth.fromEnv(Auth::oauthToken, YCKMS_OAUTH)));

        {
            // Basic AEAD example - encryption using remote encrypt/decrypt API
            System.out.println("Basic AEAD");

            Aead kmsAead = KmsClients.get(keyId).getAead(keyId);
            testAead(kmsAead, kmsAead, plaintext, context);
        }

        System.out.println();

        {
            // Envelope encryption AEAD example: encrypt data locally with pre-generated DEK and then encrypts DEK using KMS
            System.out.println("Envelope encryption");

            Aead kmsAead = KmsClients.get(keyId).getAead(keyId);
            AeadConfig.register();

            Aead encryptAead = new KmsEnvelopeAead(AeadKeyTemplates.AES256_GCM, kmsAead);
            Aead decryptAead = new KmsEnvelopeAead(AeadKeyTemplates.AES256_GCM, kmsAead);
            testAead(encryptAead, decryptAead, plaintext, context);
        }
    }

    private static void testAead(Aead encryptAead, Aead decryptAead, byte[] plaintext, byte[] context) throws GeneralSecurityException {
        byte[] ciphertext = encryptAead.encrypt(plaintext, context);
        System.out.printf("Encrypted text (base64): %s\n", Base64.getEncoder().encodeToString(ciphertext));
        System.out.printf("Encrypted text length: %d bytes\n", ciphertext.length);

        byte[] decryptedText = decryptAead.decrypt(ciphertext, context);
        System.out.printf("Decrypted text: %s\n", new String(decryptedText));

        if (Arrays.equals(plaintext, decryptedText)) {
            System.out.println("Decrypted text equals to original plaintext!");
        } else {
            System.out.println("Decrypted text differs from original plaintext!");
        }

    }

}
