package com.iplion.mesync.cloud.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Configuration
public class CryptoConfig {
    @Bean
    public KeyFactory ed25519KeyFactory() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("Ed25519");
    }
}
