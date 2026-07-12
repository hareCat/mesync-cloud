package com.iplion.mesync.cloud.error;

import com.iplion.mesync.cloud.error.api.ApiExceptionHandler;
import com.iplion.mesync.cloud.error.api.ApiErrorCode;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.logging.MdcKeys;
import com.iplion.mesync.cloud.testUtils.TestUri;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ApplicationExceptionHandlerTest {
    private final ResourceBundleMessageSource messageSource = messageSource();
    private final ApiExceptionHandler apiExceptionHandler = new ApiExceptionHandler(messageSource);

    @Test
    void handleApiExceptionFallsBackToEnglishMessage() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(TestUri.REGISTER_URI);
        LocaleContextHolder.setLocale(Locale.forLanguageTag("fr"));

        ProblemDetail problemDetail = apiExceptionHandler.handleApiException(
            DeviceRegistrationException.invalidInvite("missing invite"),
            request
        );

        assertThat(problemDetail.getDetail()).isEqualTo("Invalid invite");
        assertThat(problemDetail.getProperties()).containsEntry(
            "code",
            ApiErrorCode.REGISTRATION_INVALID_INVITE.name()
        );
    }

    @AfterEach
    void clearMdc() {
        MDC.clear();
        LocaleContextHolder.resetLocaleContext();
    }

    @Test
    void handleApiExceptionReturnsProblemDetailFromApiException() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String requestId = "test-request-id";
        MDC.put(MdcKeys.REQUEST_ID, requestId);
        when(request.getRequestURI()).thenReturn(TestUri.REGISTER_URI);
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        ProblemDetail problemDetail = apiExceptionHandler.handleApiException(
            DeviceRegistrationException.invalidInvite("missing invite"),
            request
        );

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(problemDetail.getTitle()).isEqualTo(HttpStatus.BAD_REQUEST.getReasonPhrase());
        assertThat(problemDetail.getDetail()).isEqualTo("Invalid invite");
        assertThat(problemDetail.getInstance()).hasToString(TestUri.REGISTER_URI);
        assertThat(problemDetail.getProperties()).containsKey("timestamp");
        assertThat(problemDetail.getProperties()).containsEntry(
            "code",
            ApiErrorCode.REGISTRATION_INVALID_INVITE.name()
        );
        assertThat(problemDetail.getProperties()).containsEntry("requestId", requestId);
    }

    @Test
    void handleApiExceptionReturnsLocalizedProblemDetail() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(TestUri.REGISTER_URI);
        LocaleContextHolder.setLocale(Locale.forLanguageTag("ru"));

        ProblemDetail problemDetail = apiExceptionHandler.handleApiException(
            DeviceRegistrationException.invalidInvite("missing invite"),
            request
        );

        assertThat(problemDetail.getDetail()).isEqualTo("Недействительное приглашение");
        assertThat(problemDetail.getProperties()).containsEntry(
            "code",
            ApiErrorCode.REGISTRATION_INVALID_INVITE.name()
        );
    }

    @Test
    void handleGenericExceptionReturnsSafeInternalServerErrorProblemDetail() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(TestUri.INVITE_URI);
        LocaleContextHolder.setLocale(Locale.ENGLISH);

        ProblemDetail problemDetail = apiExceptionHandler.handleGenericException(
            new IllegalStateException("boom"),
            request
        );

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(problemDetail.getTitle()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
        assertThat(problemDetail.getDetail()).isEqualTo(
            "Request could not be processed. Please try again later."
        );
        assertThat(problemDetail.getInstance()).hasToString(TestUri.INVITE_URI);
        assertThat(problemDetail.getProperties()).containsKey("timestamp");
        assertThat(problemDetail.getProperties()).containsEntry("code", ApiErrorCode.INTERNAL_ERROR.name());
    }

    private ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("messages");
        source.setDefaultEncoding("UTF-8");
        source.setFallbackToSystemLocale(false);
        return source;
    }
}
