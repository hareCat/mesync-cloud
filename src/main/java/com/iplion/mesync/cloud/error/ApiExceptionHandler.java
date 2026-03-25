package com.iplion.mesync.cloud.error;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.time.Instant;

@Slf4j
@RestControllerAdvice
public class ApiExceptionHandler {
    private static final String SAFE_5XX_MESSAGE = "Request could not be processed. Please try again later.";

    private ProblemDetail problemDetail(HttpStatus status, String clientMessage, URI uri) {
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(status, clientMessage);
        detail.setTitle(status.getReasonPhrase());
        detail.setInstance(uri);
        detail.setProperty("timestamp", Instant.now());

        return detail;
    }

    @ExceptionHandler(ApiException.class)
    public ProblemDetail handleApiException(ApiException e, HttpServletRequest request) {
        if (e.getHttpStatus().is5xxServerError()) {
            log.error(e.getMessage(), e);
        } else {
            log.warn(e.getMessage());
        }

        return problemDetail(e.getHttpStatus(),
            e.getClientMessage(),
            URI.create(request.getRequestURI()));
    }

    @ExceptionHandler(RuntimeException.class)
    public ProblemDetail handleGenericException(RuntimeException e, HttpServletRequest request) {
        log.error("Unexpected error", e);

        return problemDetail(HttpStatus.INTERNAL_SERVER_ERROR,
            SAFE_5XX_MESSAGE,
            URI.create(request.getRequestURI())
        );
    }


}
