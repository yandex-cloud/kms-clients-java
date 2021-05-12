package com.yandex.cloud.kms.providers.examples;

import org.apache.commons.lang3.Validate;

class TinkExampleUtil {
    private TinkExampleUtil() {
    }

    public static String argAsString(String[] args, int index) {
        Validate.isTrue(index < args.length, "args[%s] is missing", index);
        return args[index];
    }
}
