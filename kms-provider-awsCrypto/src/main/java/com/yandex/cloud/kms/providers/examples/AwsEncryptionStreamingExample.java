package com.yandex.cloud.kms.providers.examples;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.yandex.cloud.kms.providers.awscrypto.YcKmsMasterKeyProvider;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.Validate;
import yandex.cloud.sdk.auth.Credentials;
import yandex.cloud.sdk.auth.OauthToken;

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

    public static void main(final String[] args) throws IOException {
        String token = ExampleUtil.envAsString("YCKMS_OAUTH");
        String keyId = ExampleUtil.argAsString(args, 0);
        File plaintextFile = new File(ExampleUtil.argAsString(args, 1));

        Credentials credentials = new OauthToken(token);

        File encryptedFile = ExampleUtil.fileWithSuffix(plaintextFile, ".encrypted");
        File decryptedFile = ExampleUtil.fileWithSuffix(plaintextFile, ".decrypted");

        encryptToFile(credentials, keyId, plaintextFile, encryptedFile);
        System.out.println("Ciphertext file: " + encryptedFile.toString());
        System.out.println("Ciphertext file length: " + Files.size(encryptedFile.toPath()));

        decryptFromFile(credentials, encryptedFile, decryptedFile);
        System.out.println("Decrypted file: " + decryptedFile.toString());
        System.out.println("Decrypted file length: " + Files.size(decryptedFile.toPath()));

        Validate.isTrue(FileUtils.contentEquals(plaintextFile, decryptedFile), "Decrypted text differs from original plaintext!!");
    }

    /*
     *  Example of streaming encryption with AwsCrypto
     */
    private static void encryptToFile(Credentials credentials, String keyId, File plaintextFile, File encryptedFile) {
        YcKmsMasterKeyProvider provider = YcKmsMasterKeyProvider.builder()
                .setCredentialsSupplier(() -> credentials)
                .setKeyId(keyId)
                .build();
        AwsCrypto awsCrypto = new AwsCrypto();

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
    private static void decryptFromFile(Credentials credentials, File encryptedFile, File decryptedFile) {
        AwsCrypto awsCrypto = new AwsCrypto();
        YcKmsMasterKeyProvider provider = YcKmsMasterKeyProvider.builder()
                .setCredentialsSupplier(() -> credentials)
                .build();

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
