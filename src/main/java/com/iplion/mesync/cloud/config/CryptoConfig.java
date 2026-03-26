package com.iplion.mesync.cloud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;

@Configuration
public class CryptoConfig {
    @Bean
    public KeyFactory ed25519KeyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance("Ed25519");
    }
}
