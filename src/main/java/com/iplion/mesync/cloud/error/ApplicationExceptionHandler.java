package com.iplion.mesync.cloud.error;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.net.URI;
import java.time.Instant;

@Slf4j
@RestControllerAdvice
public class ApplicationExceptionHandler {
    private static final String SAFE_5XX_MESSAGE = "Request could not be processed. Please try again later.";

    private ProblemDetail problemDetail(HttpStatus status, String clientMessage, HttpServletRequest request) {
        ProblemDetail detail = ProblemDetail.forStatusAndDetail(status, clientMessage);
        detail.setTitle(status.getReasonPhrase());
        detail.setInstance(URI.create(request.getRequestURI()));
        detail.setProperty("timestamp", Instant.now());

        return detail;
    }

    @ExceptionHandler(ApplicationException.class)
    public ProblemDetail handleApplicationException(ApplicationException e, HttpServletRequest request) {
        if (e.getHttpStatus().is5xxServerError()) {
            log.error(e.getMessage(), e);
        } else {
            log.warn(e.getMessage(), e);
        }

        return problemDetail(e.getHttpStatus(), e.getClientMessage(), request);
    }

    // === 400: bad JSON ===
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ProblemDetail handleBadJson(HttpMessageNotReadableException e, HttpServletRequest request) {
        log.warn(e.getMessage(), e);

        return problemDetail(
            HttpStatus.BAD_REQUEST,
            "Malformed JSON request",
            request
        );
    }

    // === 400: validation (@Valid) ===
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException e, HttpServletRequest request) {
        log.warn(e.getMessage(), e);

        return problemDetail(
            HttpStatus.BAD_REQUEST,
            "Validation failed",
            request
        );
    }

    // === 400: params / path / type ===
    @ExceptionHandler({
        MissingServletRequestParameterException.class,
        MethodArgumentTypeMismatchException.class
    })
    public ProblemDetail handleBadRequest(Exception e, HttpServletRequest request) {
        log.warn(e.getMessage(), e);

        return problemDetail(
            HttpStatus.BAD_REQUEST,
            "Invalid request parameters",
            request
        );
    }

    // === 401 ===
    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleAuth(Exception e, HttpServletRequest request) {
        log.warn(e.getMessage(), e);

        return problemDetail(
            HttpStatus.UNAUTHORIZED,
            "Unauthorized",
            request
        );
    }

    // === 403 ===
    @ExceptionHandler({
        AccessDeniedException.class,
        AuthorizationDeniedException.class
    })
    public ProblemDetail handleAccessDenied(Exception e, HttpServletRequest request) {
        log.warn(e.getMessage(), e);

        return problemDetail(
            HttpStatus.FORBIDDEN,
            "Access denied",
            request
        );
    }

     // === fallback ===
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleGenericException(Exception e, HttpServletRequest request) {
        log.error("Unexpected error", e);

        return problemDetail(HttpStatus.INTERNAL_SERVER_ERROR,
            SAFE_5XX_MESSAGE,
            request
        );
    }

}
