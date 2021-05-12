package com.yandex.cloud.kms.providers.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.yandex.cloud.kms.providers.awscrypto.YcKmsMasterKeyProvider;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.Validate;
import yandex.cloud.sdk.auth.Auth;
import yandex.cloud.sdk.auth.provider.CredentialProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;

/**
 * Example of streaming encryption / decryption using YC KMS provider for AWS Encryption SDK
 */
public class AwsEncryptionStreamingExample {
    private static final String YCKMS_OAUTH = "YCKMS_OAUTH";

    public static void main(final String[] args) throws IOException {
        String keyId = AwsExampleUtil.argAsString(args, 0);
        File plaintextFile = new File(AwsExampleUtil.argAsString(args, 1));

        CredentialProvider credentialProvider = Auth.oauthTokenBuilder().fromEnv(YCKMS_OAUTH).build();

        File encryptedFile = AwsExampleUtil.fileWithSuffix(plaintextFile, ".encrypted");
        File decryptedFile = AwsExampleUtil.fileWithSuffix(plaintextFile, ".decrypted");

        encryptToFile(credentialProvider, keyId, plaintextFile, encryptedFile);
        System.out.printf("Ciphertext file: %s\n", encryptedFile.toString());
        System.out.printf("Ciphertext file length: %d\n", Files.size(encryptedFile.toPath()));

        decryptFromFile(credentialProvider, encryptedFile, decryptedFile);
        System.out.printf("Decrypted file: %s\n", decryptedFile.toString());
        System.out.printf("Decrypted file length: %d\n", Files.size(decryptedFile.toPath()));

        Validate.isTrue(FileUtils.contentEquals(plaintextFile, decryptedFile),
                "Test FAILED: decrypted text differs from original plaintext");
        System.out.println("Test PASSED");
    }

    /*
     *  Example of streaming encryption with AwsCrypto
     */
    private static void encryptToFile(CredentialProvider credentialProvider, String keyId, File plaintextFile, File encryptedFile) {
        YcKmsMasterKeyProvider provider = new YcKmsMasterKeyProvider()
                .withCredentials(credentialProvider)
                .withKeyId(keyId);
        AwsCrypto awsCrypto = AwsCrypto.standard();

        try (
                InputStream inputStream = new FileInputStream(plaintextFile);
                OutputStream outputStream = awsCrypto.createEncryptingStream(provider, new FileOutputStream(encryptedFile))
        ) {
            IOUtils.copy(inputStream, outputStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /*
     *  Example of streaming decryption with AwsCrypto
     */
    private static void decryptFromFile(CredentialProvider credentialProvider, File encryptedFile, File decryptedFile) {
        AwsCrypto awsCrypto = AwsCrypto.standard();
        YcKmsMasterKeyProvider provider = new YcKmsMasterKeyProvider()
                .withCredentials(credentialProvider);

        try (
                InputStream inputStream = awsCrypto.createDecryptingStream(provider, new FileInputStream(encryptedFile));
                OutputStream outputStream = new FileOutputStream(decryptedFile)
        ) {
            IOUtils.copy(inputStream, outputStream);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
