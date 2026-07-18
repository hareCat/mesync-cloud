package com.iplion.mesync.cloud;

import com.github.benmanes.caffeine.cache.Cache;
import com.iplion.mesync.cloud.config.PostgresContainerConfig;
import com.iplion.mesync.cloud.config.RedisContainerConfig;
import org.junit.jupiter.api.AfterEach;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;
import java.util.Objects;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({RedisContainerConfig.class, PostgresContainerConfig.class})
@AutoConfigureMockMvc
public abstract class BaseIT {
    @MockitoBean
    JwtDecoder jwtDecoder;

    @Autowired
    JdbcTemplate jdbcTemplate;

    @Autowired
    RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    List<Cache<?, ?>> caches = List.of();

    @AfterEach
    void cleanUpTestState() {
        jdbcTemplate.execute("""
                TRUNCATE TABLE messages, devices, users
                RESTART IDENTITY
                CASCADE
            """);

        try (var connection = Objects.requireNonNull(redisTemplate.getConnectionFactory()).getConnection()) {
            connection.serverCommands().flushDb();
        }

        caches.forEach(Cache::invalidateAll);
        SecurityContextHolder.clearContext();
        MDC.clear();
    }
}
