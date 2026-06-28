package com.iplion.mesync.cloud;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;
import org.springframework.security.core.context.SecurityContextHolder;

@ExtendWith(MockitoExtension.class)
public abstract class BaseUnitTest {
    @AfterEach
    void tearDownSecurityContext() {
        SecurityContextHolder.clearContext();
        MDC.clear();
    }
}
