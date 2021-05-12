package com.yandex.cloud.kms.providers.examples;

import org.apache.commons.lang3.Validate;

import java.io.File;

class AwsExampleUtil {
    private AwsExampleUtil() {
    }

    public static String argAsString(String[] args, int index) {
        Validate.isTrue(index < args.length, "args[%s] is missing", index);
        return args[index];
    }

    public static File fileWithSuffix(File file, String suffix) {
        return new File(file.toString() + suffix);
    }
}
