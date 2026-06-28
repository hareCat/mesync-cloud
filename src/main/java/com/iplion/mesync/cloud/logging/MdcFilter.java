package com.iplion.mesync.cloud.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NonNull;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class MdcFilter extends OncePerRequestFilter {
    private static final String REQUEST_ID_HEADER = "X-Request-Id";

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String requestId = getRequestId(request);
            MDC.put(MdcKeys.REQUEST_ID, requestId);
            MDC.put(MdcKeys.METHOD, request.getMethod());
            MDC.put(MdcKeys.PATH, request.getRequestURI());
            response.setHeader(REQUEST_ID_HEADER, requestId);

            filterChain.doFilter(request, response);
        } finally {
            MDC.clear();
        }
    }

    private String getRequestId(HttpServletRequest request) {
        String requestId = request.getHeader(REQUEST_ID_HEADER);

        return requestId == null || requestId.isBlank()
            ? UUID.randomUUID().toString()
            : requestId;
    }
}
