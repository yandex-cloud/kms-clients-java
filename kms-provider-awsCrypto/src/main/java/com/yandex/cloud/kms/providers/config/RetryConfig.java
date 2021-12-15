package com.yandex.cloud.kms.providers.config;


public class RetryConfig {
    private int maxRetry = 3;
    private int delay = 2;
    private int maxDelay = 2;

    public RetryConfig(int maxRetry, int delay, int maxDelay) {
        this.delay = delay;
        this.maxRetry = maxRetry;
        this.maxDelay = maxDelay;
    }

    public RetryConfig() {

    }

    public int getDelay() {
        return delay;
    }

    public int getMaxRetry() {
        return maxRetry;
    }

    public int getMaxDelay() {
        return maxDelay;
    }
}