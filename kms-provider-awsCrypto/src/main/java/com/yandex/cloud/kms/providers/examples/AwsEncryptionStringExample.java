package com.yandex.cloud.kms.providers.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.yandex.cloud.kms.providers.awscrypto.YcKmsMasterKeyProvider;
import org.apache.commons.lang3.Validate;
import yandex.cloud.sdk.auth.Auth;
import yandex.cloud.sdk.auth.provider.CredentialProvider;

/**
 * Basic string encryption / decryption example using YC KMS provider for AWS Encryption SDK
 */
public class AwsEncryptionStringExample {
    private static final String YCKMS_OAUTH = "YCKMS_OAUTH";

    public static void main(final String[] args) {
        String keyId = AwsExampleUtil.argAsString(args, 0);
        String plaintext = AwsExampleUtil.argAsString(args, 1);

        CredentialProvider credentialProvider = Auth.oauthTokenBuilder().fromEnv(YCKMS_OAUTH).build();

        String encrypted = encrypt(credentialProvider, keyId, plaintext);
        System.out.printf("Ciphertext: %s\n", encrypted);
        System.out.printf("Ciphertext length: %d\n", encrypted.length());

        String decrypted = decrypt(credentialProvider, encrypted);
        System.out.printf("Decrypted: %s\n", decrypted);
        System.out.printf("Decrypted length: %d\n", decrypted.length());

        Validate.isTrue(decrypted.equals(plaintext),
                "Test FAILED: decrypted text differs from original plaintext");
        System.out.println("Test PASSED");
    }

    /*
     *  Example of basic encryption with AwsCrypto
     */
    private static String encrypt(CredentialProvider credentialProvider, String keyId, String plaintext) {
        YcKmsMasterKeyProvider provider = new YcKmsMasterKeyProvider()
                .withCredentials(credentialProvider)
                .withKeyId(keyId);
        AwsCrypto awsCrypto = AwsCrypto.standard();

        return awsCrypto.encryptString(provider, plaintext).getResult();
    }

    /*
     *  Example of basic decryption with AwsCrypto
     */
    private static String decrypt(CredentialProvider credentialProvider, String ciphertext) {
        YcKmsMasterKeyProvider provider = new YcKmsMasterKeyProvider()
                .withCredentials(credentialProvider);
        AwsCrypto awsCrypto = AwsCrypto.standard();

        return awsCrypto.decryptString(provider, ciphertext).getResult();
    }
}
