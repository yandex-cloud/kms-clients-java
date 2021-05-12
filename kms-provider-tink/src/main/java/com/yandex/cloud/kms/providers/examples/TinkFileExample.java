package com.yandex.cloud.kms.providers.examples;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.yandex.cloud.kms.providers.tink.YcKmsClient;
import yandex.cloud.sdk.auth.Auth;
import yandex.cloud.sdk.auth.provider.CredentialProvider;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;

/**
 * This example shows how to protect Tink keyset with master key located in YC KMS
 */
public class TinkFileExample {
    private static final String YCKMS_OAUTH = "YCKMS_OAUTH";

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        String keyId = TinkExampleUtil.argAsString(args, 0); // key id as a first argument
        String keyUri = String.format("yc-kms://%s", keyId);
        String filename = TinkExampleUtil.argAsString(args, 1); // key store file name to be created as a second argument

        // first let's register our YC KMS client with Tink clients' registry
        CredentialProvider credentialProvider = Auth.oauthTokenBuilder().fromEnv(YCKMS_OAUTH).build();
        KmsClients.add(new YcKmsClient(credentialProvider)); // take OAUTH token from env

        // retrieve YC KMS client according to the key prefix
        KmsClient kmsClient = KmsClients.get(keyUri);
        // get kms-powered aead primitive
        Aead ycKmsAead = kmsClient.getAead(keyUri);

        // let tink know we'd like to use AEAD primitive
        AeadConfig.register();
        // create new local AES-GCM-128bit key set
        KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM);
        // write key set file to disk encrypted with yc kms master key
        keysetHandle.write(JsonKeysetWriter.withFile(new File(filename)), ycKmsAead);

        System.out.printf("Newly generated key was written to file with name %s\n", filename);
        System.out.println("File content");
        System.out.println("------------");

        // print content of the file written
        Files.readAllLines(Paths.get(filename)).forEach(System.out::println);
    }


}
