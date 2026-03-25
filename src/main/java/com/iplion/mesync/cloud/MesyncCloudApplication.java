package com.iplion.mesync.cloud;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class MesyncCloudApplication {

    //TODO add MDC
    public static void main(String[] args) {
        SpringApplication.run(MesyncCloudApplication.class, args);
    }

}
