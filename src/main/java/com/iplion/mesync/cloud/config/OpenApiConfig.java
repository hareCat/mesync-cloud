package com.iplion.mesync.cloud.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI api() {
        return new OpenAPI()
            .info(new Info()
                .title("meSync Cloud API")
                .description("End-to-end encrypted device registration, invite exchange, revocation, and message sync API. " +
                    "Additional-device registration uses a four-step invite flow: invite, public keys, encrypted master key, register.")
                .version("v1"))
            .components(new Components().addSecuritySchemes("bearerAuth",
                new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
            ))
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }

    @Bean
    public OpenApiCustomizer commonResponsesCustomizer() {
        return openApi -> openApi.getPaths().values().forEach(pathItem ->
            pathItem.readOperations().forEach(operation -> {
                operation.getResponses().addApiResponse("400", new ApiResponse().description("Invalid request"));
                operation.getResponses().addApiResponse("401", new ApiResponse().description("Unauthorized"));
                operation.getResponses().addApiResponse("403", new ApiResponse().description("Forbidden"));
            })
        );
    }
}
