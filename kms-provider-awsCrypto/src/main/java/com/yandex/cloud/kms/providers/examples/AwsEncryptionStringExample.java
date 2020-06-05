package com.yandex.cloud.kms.providers.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.yandex.cloud.kms.providers.awscrypto.YcKmsMasterKeyProvider;
import org.apache.commons.lang3.Validate;
import yandex.cloud.sdk.auth.Credentials;
import yandex.cloud.sdk.auth.OauthToken;

/**
 * Basic string encryption / decryption example using YC KMS provider for AWS Encryption SDK
 */
public class AwsEncryptionStringExample {

    public static void main(final String[] args) {
        String token = ExampleUtil.envAsString("YCKMS_OAUTH");
        String keyId = ExampleUtil.argAsString(args, 0);
        String plaintext = ExampleUtil.argAsString(args, 1);

        Credentials credentials = new OauthToken(token);

        String encrypted = encrypt(credentials, keyId, plaintext);
        System.out.printf("Ciphertext: %s\n", encrypted);
        System.out.printf("Ciphertext length: %d\n", encrypted.length());

        String decrypted = decrypt(credentials, encrypted);
        System.out.printf("Decrypted: %s\n", decrypted);
        System.out.printf("Decrypted length: %d\n", decrypted.length());

        Validate.isTrue(decrypted.equals(plaintext),
                "Test FAILED: decrypted text differs from original plaintext");
        System.out.println("Test PASSED");
    }

    /*
     *  Example of basic encryption with AwsCrypto
     */
    private static String encrypt(Credentials credentials, String keyId, String plaintext) {
        YcKmsMasterKeyProvider provider = YcKmsMasterKeyProvider.builder()
                .setCredentialsSupplier(() -> credentials)
                .setKeyId(keyId)
                .build();
        AwsCrypto awsCrypto = new AwsCrypto();

        return awsCrypto.encryptString(provider, plaintext).getResult();
    }

    /*
     *  Example of basic decryption with AwsCrypto
     */
    private static String decrypt(Credentials credentials, String ciphertext) {
        YcKmsMasterKeyProvider provider = YcKmsMasterKeyProvider.builder()
                .setCredentialsSupplier(() -> credentials)
                .build();
        AwsCrypto awsCrypto = new AwsCrypto();

        return awsCrypto.decryptString(provider, ciphertext).getResult();
    }
}
