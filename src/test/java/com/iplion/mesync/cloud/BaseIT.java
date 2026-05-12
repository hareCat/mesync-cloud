package com.iplion.mesync.cloud;

import com.iplion.mesync.cloud.config.PostgresContainerConfig;
import com.iplion.mesync.cloud.config.RedisContainerConfig;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({RedisContainerConfig.class, PostgresContainerConfig.class})
@AutoConfigureMockMvc
public abstract class BaseIT {
    @MockitoBean
    JwtDecoder jwtDecoder;
}