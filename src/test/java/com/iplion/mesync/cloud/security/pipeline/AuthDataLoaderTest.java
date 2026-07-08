package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.error.InvalidTokenException;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.logging.MdcKeys;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.AuthContextService;
import com.iplion.mesync.cloud.security.crypto.KeySignatureService;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.request.common.UnregisteredDeviceAuthRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthDataLoaderTest extends BaseUnitTest {
    @Mock
    AuthContextService authContextService;

    @Mock
    KeySignatureService keySignatureService;

    AuthDataLoader authDataLoader;

    TestPipelineFactory.TestContext testContext;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        authDataLoader = new AuthDataLoader(authContextService, keySignatureService);
        testContext = TestPipelineFactory.testContext();

        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(testContext.jwt()));
    }

    @Test
    void loadJwtData_shouldStoreJwtDataInContextAndMdc_whenJwtValid() {
        var authPipelineContext = TestPipelineFactory.registeredAuthPipelineContext(testContext);

        authDataLoader.loadJwtData(authPipelineContext);

        assertThat(authPipelineContext.getJwtUserData().authId()).isEqualTo(testContext.userAuthId());
        assertThat(MDC.get(MdcKeys.JWT_AUTH_ID)).isEqualTo(testContext.userAuthId().toString());
        assertThat(MDC.get(MdcKeys.CLIENT_ID)).isEqualTo(DeviceType.MOBILE.getClientId());
    }

    @Test
    void loadJwtData_shouldThrow_whenJwtInvalid() {
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(mock(Jwt.class)));
        var authPipelineContext = TestPipelineFactory.registeredAuthPipelineContext(testContext);

        assertThatThrownBy(() -> authDataLoader.loadJwtData(authPipelineContext))
            .isInstanceOf(AuthException.class)
            .hasCauseInstanceOf(InvalidTokenException.class);
    }

    @Test
    void loadRegisteredDeviceAuthData_shouldLoadAuthDataAndPutItToMdc() {
        var authPipelineContext = TestPipelineFactory.registeredAuthPipelineContext(testContext);

        when(authContextService.getFullAuthContext(any())).thenReturn(testContext.authData());

        authDataLoader.loadRegisteredDeviceAuthData(authPipelineContext);

        verify(authContextService).getFullAuthContext(eq(testContext.devicePublicId()));

        assertThat(authPipelineContext.getAuthData()).isEqualTo(testContext.authData());
        assertAuthDataMdc(testContext.authData());
    }

    @Test
    void loadUnregisteredDeviceAuthData_shouldCreateAuthDataAndPutItToMdc_whenUserFound() {
        var authPipelineContext = TestPipelineFactory.unregisteredAuthPipelineContext(testContext);
        authPipelineContext.setJwtUserData(testContext.jwtUserData());

        when(authContextService.findUserAuthContext(any()))
            .thenReturn(Optional.of(testContext.authData().userAuthData()));
        when(keySignatureService.createPublicKey(any())).thenReturn(testContext.publicKey());

        authDataLoader.loadUnregisteredDeviceAuthData(authPipelineContext);

        verify(authContextService).findUserAuthContext(eq(testContext.userAuthId()));
        verify(keySignatureService).createPublicKey(eq(testContext.publicKeyBytes()));

        assertThat(authPipelineContext.getAuthData().userAuthData()).isEqualTo(testContext.authData().userAuthData());
        assertThat(authPipelineContext.getAuthData().deviceAuthData().ownerAuthId()).isEqualTo(testContext.userAuthId());
        assertThat(authPipelineContext.getAuthData().deviceAuthData().deviceType()).isEqualTo(DeviceType.MOBILE);
        assertThat(authPipelineContext.getAuthData().deviceAuthData().publicKey()).isEqualTo(testContext.publicKey());
        assertAuthDataMdc(authPipelineContext.getAuthData());
    }

    @Test
    void loadUnregisteredDeviceAuthData_shouldCreateTemporaryUserAuthData_whenUserNotFound() {
        var authPipelineContext = TestPipelineFactory.unregisteredAuthPipelineContext(testContext);
        authPipelineContext.setJwtUserData(testContext.jwtUserData());

        when(authContextService.findUserAuthContext(any()))
            .thenReturn(Optional.empty());
        when(keySignatureService.createPublicKey(any()))
            .thenReturn(testContext.publicKey());

        authDataLoader.loadUnregisteredDeviceAuthData(authPipelineContext);

        assertThat(authPipelineContext.getAuthData().userAuthData().id()).isNull();
        assertThat(authPipelineContext.getAuthData().userAuthData().authId()).isEqualTo(testContext.userAuthId());
        assertThat(authPipelineContext.getAuthData().userAuthData().keyVersion()).isNull();
    }

    @Test
    void loadUnregisteredDeviceAuthData_shouldThrowBadRequest_whenRequestPublicKeyInvalid() {
        var authPipelineContext = unregisteredAuthPipelineContextWithInvalidBase64PublicKey();
        authPipelineContext.setJwtUserData(testContext.jwtUserData());

        when(authContextService.findUserAuthContext(any()))
            .thenReturn(Optional.of(testContext.authData().userAuthData()));

        assertThatThrownBy(() -> authDataLoader.loadUnregisteredDeviceAuthData(authPipelineContext))
            .isInstanceOfSatisfying(AuthException.class, e -> {
                assertThat(e.getHttpStatus()).isEqualTo(HttpStatus.BAD_REQUEST);
                assertThat(e.getMessage()).contains("Invalid base64 publicKey");
            });
    }

    private AuthPipelineContext<UnregisteredDeviceAuthRequest> unregisteredAuthPipelineContextWithInvalidBase64PublicKey() {
        return new AuthPipelineContext<>(new TestPipelineFactory.TestUnregisteredDeviceAuthRequest(
            "test-signature",
            testContext.nonce(),
            "invalid base64 !"
        ));
    }

    private void assertAuthDataMdc(AuthData authData) {
        assertThat(MDC.get(MdcKeys.USER_ID)).isEqualTo(mdcValue(authData.userAuthData().id()));
        assertThat(MDC.get(MdcKeys.USER_AUTH_ID)).isEqualTo(mdcValue(authData.userAuthData().authId()));
        assertThat(MDC.get(MdcKeys.DEVICE_ID)).isEqualTo(mdcValue(authData.deviceAuthData().id()));
        assertThat(MDC.get(MdcKeys.DEVICE_PUBLIC_ID)).isEqualTo(mdcValue(authData.deviceAuthData().publicId()));
        assertThat(MDC.get(MdcKeys.DEVICE_TYPE)).isEqualTo(mdcValue(authData.deviceAuthData().deviceType()));
    }

    private String mdcValue(Object value) {
        return value == null ? null : value.toString();
    }

}
