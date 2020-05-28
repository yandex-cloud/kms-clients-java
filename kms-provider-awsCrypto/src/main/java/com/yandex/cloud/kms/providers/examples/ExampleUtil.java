package com.yandex.cloud.kms.providers.examples;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

class ExampleUtil {
    private ExampleUtil() {
    }

    public static String argAsString(String[] args, int index) {
        Validate.isTrue(index < args.length, "args[%s] is missing", index);
        return args[index];
    }

    public static String envAsString(String name) {
        String env = System.getenv(name);
        Validate.isTrue(StringUtils.isNotBlank(env), "Environment variable %s is missing", name);
        return env;
    }

    public static int envAsInt(String name) {
        String env = System.getenv(name);
        try {
            return Integer.parseInt(env);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    String.format("Environment variable %s is missing or not integer", name), e
            );
        }
    }

    public static File fileWithSuffix(File file, String suffix) {
        return new File(file.toString() + suffix);
    }

    public static List<String> split(String commaSeparatedValues) {
        return Arrays.stream(commaSeparatedValues.split(","))
                .map(String::trim)
                .collect(Collectors.toList());
    }
}
