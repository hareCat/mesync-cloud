package com.iplion.mesync.cloud.error;

import com.iplion.mesync.cloud.error.api.ApiExceptionHandler;
import com.iplion.mesync.cloud.error.api.DeviceRegistrationException;
import com.iplion.mesync.cloud.logging.MdcKeys;
import com.iplion.mesync.cloud.testUtils.TestUri;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ApplicationExceptionHandlerTest {
    private final ApiExceptionHandler apiExceptionHandler = new ApiExceptionHandler();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void handleApiExceptionReturnsProblemDetailFromApiException() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String requestId = "test-request-id";
        MDC.put(MdcKeys.REQUEST_ID, requestId);
        when(request.getRequestURI()).thenReturn(TestUri.REGISTER_URI);

        ProblemDetail problemDetail = apiExceptionHandler.handleApiException(
            DeviceRegistrationException.invalidInvite("missing invite"),
            request
        );

        assertThat(problemDetail.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(problemDetail.getTitle()).isEqualTo(HttpStatus.BAD_REQUEST.getReasonPhrase());
        assertThat(problemDetail.getDetail()).isEqualTo("Invalid invite");
        assertThat(problemDetail.getInstance()).hasToString(TestUri.REGISTER_URI);
        assertThat(problemDetail.getProperties()).containsKey("timestamp");
        assertThat(problemDetail.getProperties()).containsEntry("requestId", requestId);
    }

    @Test
    void handleGenericExceptionReturnsSafeInternalServerErrorProblemDetail() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRequestURI()).thenReturn(TestUri.INVITE_URI);

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
    }
}
