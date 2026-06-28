package com.iplion.mesync.cloud.logging;

import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class MdcFilterTest {
    private final MdcFilter mdcFilter = new MdcFilter();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void doFilter_shouldPutRequestDataToMdcAndClearItAfterRequest() throws ServletException, IOException {
        String requestId = UUID.randomUUID().toString();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/messages");
        request.addHeader("X-Request-Id", requestId);
        MockHttpServletResponse response = new MockHttpServletResponse();

        mdcFilter.doFilter(request, response, (req, res) -> {
            assertThat(MDC.get(MdcKeys.REQUEST_ID)).isEqualTo(requestId);
            assertThat(MDC.get(MdcKeys.METHOD)).isEqualTo("POST");
            assertThat(MDC.get(MdcKeys.PATH)).isEqualTo("/api/messages");
        });

        assertThat(response.getHeader("X-Request-Id")).isEqualTo(requestId);
        assertThat(MDC.getCopyOfContextMap()).isNull();
    }

    @Test
    void doFilter_shouldGenerateRequestId_whenHeaderMissing() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/messages");
        MockHttpServletResponse response = new MockHttpServletResponse();

        mdcFilter.doFilter(
            request, response,
            (req, res) -> assertThat(MDC.get(MdcKeys.REQUEST_ID)).isNotBlank()
        );

        assertThat(response.getHeader("X-Request-Id")).isNotBlank();
        assertThat(MDC.getCopyOfContextMap()).isNull();
    }
}
