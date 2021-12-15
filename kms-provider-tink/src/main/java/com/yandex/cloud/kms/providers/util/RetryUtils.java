package com.yandex.cloud.kms.providers.util;

import com.yandex.cloud.kms.providers.config.RetryConfig;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import net.jodah.failsafe.RetryPolicy;

import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Set;

public class RetryUtils {

    private final static Set<Status.Code> retryExceptionCodes = new HashSet<Status.Code>() {{
        add(Status.UNAVAILABLE.getCode());
        add(Status.DEADLINE_EXCEEDED.getCode());
        add(Status.INTERNAL.getCode());
    }};

    public static <T> RetryPolicy<T> createRetryPolicy(RetryConfig retryConfig) {
        if (retryConfig == null) {
            retryConfig = new RetryConfig();
        }

        return new RetryPolicy<T>()
                .handleIf((res, ex) -> {
                    if (!(ex instanceof StatusRuntimeException)) {
                        return false;
                    }
                    StatusRuntimeException exception = (StatusRuntimeException) ex;
                    return retryExceptionCodes.contains(exception.getStatus().getCode());
                })
                .withBackoff(retryConfig.getDelay(), retryConfig.getMaxDelay(), ChronoUnit.MILLIS)
                .withMaxRetries(retryConfig.getMaxRetry());
    }

}
