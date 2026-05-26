package com.iplion.mesync.cloud;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class MesyncCloudApplication {

    // TODO add MDC
    // TODO add revoke device(s)
    // TODO add update master key after revoke
    // TODO implement FCM (push notifications)
    // TODO add last device message id to caffeine deviceAuthData
    //      and check request lastMessageId with saved device lastMessageId from caffeine
    // TODO add handlers for postgres exceptions
    // TODO add swagger description
    public static void main(String[] args) {
        SpringApplication.run(MesyncCloudApplication.class, args);
    }

}
