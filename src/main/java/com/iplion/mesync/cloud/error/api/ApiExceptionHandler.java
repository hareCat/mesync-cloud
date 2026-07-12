package com.iplion.mesync.cloud.error.api;

import com.iplion.mesync.cloud.logging.MdcKeys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
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
@RequiredArgsConstructor
public class ApiExceptionHandler {
    private final MessageSource messageSource;

    private ProblemDetail problemDetail(
        HttpStatus status,
        ApiErrorCode errorCode,
        Object[] messageArgs,
        HttpServletRequest request
    ) {
        String localizedMessage = resolveLocalizedMessage(errorCode, messageArgs);

        ProblemDetail detail = ProblemDetail.forStatusAndDetail(status, localizedMessage);
        detail.setTitle(status.getReasonPhrase());
        detail.setInstance(URI.create(request.getRequestURI()));
        detail.setProperty("timestamp", Instant.now());
        detail.setProperty("code", errorCode.name());
        String requestId = MDC.get(MdcKeys.REQUEST_ID);
        if (requestId != null) {
            detail.setProperty("requestId", requestId);
        }

        return detail;
    }

    private String resolveLocalizedMessage(ApiErrorCode errorCode, Object[] messageArgs) {
        return messageSource.getMessage(
            errorCode.getMessageKey(),
            messageArgs,
            errorCode.name(),
            LocaleContextHolder.getLocale()
        );
    }

    @ExceptionHandler(ApiException.class)
    public ProblemDetail handleApiException(ApiException e, HttpServletRequest request) {
        if (e.getHttpStatus().is5xxServerError()) {
            log.error(e.getMessage(), e);
        } else {
            log.warn(e.getMessage(), e);
        }

        return problemDetail(e.getHttpStatus(), e.getErrorCode(), e.getMessageArgs(), request);
    }

    // === 400: bad JSON ===
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ProblemDetail handleBadJson(HttpMessageNotReadableException e, HttpServletRequest request) {
        log.warn(e.getMessage(), e);

        return problemDetail(
            HttpStatus.BAD_REQUEST,
            ApiErrorCode.MALFORMED_JSON,
            null,
            request
        );
    }

    // === 400: validation (@Valid) ===
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException e, HttpServletRequest request) {
        log.warn(e.getMessage(), e);

        return problemDetail(
            HttpStatus.BAD_REQUEST,
            ApiErrorCode.VALIDATION_FAILED,
            null,
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
            ApiErrorCode.INVALID_REQUEST_PARAMETERS,
            null,
            request
        );
    }

    // === 401 ===
    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail handleAuth(Exception e, HttpServletRequest request) {
        log.warn(e.getMessage(), e);

        return problemDetail(
            HttpStatus.UNAUTHORIZED,
            ApiErrorCode.UNAUTHORIZED,
            null,
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
            ApiErrorCode.ACCESS_DENIED,
            null,
            request
        );
    }

    // === fallback ===
    @ExceptionHandler(Exception.class)
    public ProblemDetail handleGenericException(Exception e, HttpServletRequest request) {
        log.error("Unexpected error", e);

        return problemDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            ApiErrorCode.INTERNAL_ERROR,
            null,
            request
        );
    }

}
