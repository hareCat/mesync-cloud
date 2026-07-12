package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.error.api.ApiErrorCode;
import com.iplion.mesync.cloud.error.api.AuthException;
import com.iplion.mesync.cloud.model.DeviceType;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.request.common.RegisteredDeviceAuthRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

class DeviceAuthCheckerTest extends BaseUnitTest {
    DeviceAuthChecker deviceAuthChecker;

    @BeforeEach
    void setUp() {
        deviceAuthChecker = new DeviceAuthChecker();
    }

    @Test
    void deviceOwnerCheck_shouldPass_whenJwtUserOwnsDevice() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var authPipelineContext = registeredAuthPipelineContextWithAuthData(testContext);

        deviceAuthChecker.deviceOwnerCheck(authPipelineContext);
    }

    @Test
    void deviceOwnerCheck_shouldThrow_whenOwnershipMismatch() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var authPipelineContext = registeredAuthPipelineContextWithAuthData(testContext);
        authPipelineContext.setAuthData(authData(testContext, UUID.randomUUID(), DeviceType.MOBILE));

        assertThatThrownBy(() -> deviceAuthChecker.deviceOwnerCheck(authPipelineContext))
            .isInstanceOfSatisfying(AuthException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.AUTH_DEVICE_OWNERSHIP_MISMATCH)
            );
    }

    @Test
    void deviceTypeCheck_shouldPass_whenJwtDeviceTypeMatchesDevice() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var authPipelineContext = registeredAuthPipelineContextWithAuthData(testContext);

        deviceAuthChecker.deviceTypeCheck(authPipelineContext);
    }

    @Test
    void deviceTypeCheck_shouldThrow_whenRequestDeviceTypeMismatch() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var authPipelineContext = registeredAuthPipelineContextWithAuthData(testContext);
        authPipelineContext.setAuthData(authData(testContext, testContext.userAuthId(), DeviceType.BROWSER));

        assertThatThrownBy(() -> deviceAuthChecker.deviceTypeCheck(authPipelineContext))
            .isInstanceOfSatisfying(AuthException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.AUTH_DEFAULT)
            );
    }

    private AuthPipelineContext<RegisteredDeviceAuthRequest> registeredAuthPipelineContextWithAuthData(
        TestPipelineFactory.TestContext testContext
    ) {
        var authPipelineContext = TestPipelineFactory.registeredAuthPipelineContext(testContext);
        authPipelineContext.setJwtUserData(testContext.jwtUserData());
        authPipelineContext.setAuthData(testContext.authData());
        return authPipelineContext;
    }

    private AuthData authData(
        TestPipelineFactory.TestContext testContext,
        UUID ownerAuthId,
        DeviceType deviceType
    ) {
        return new AuthData(
            testContext.authData().userAuthData(),
            new DeviceAuthData(
                1L,
                testContext.devicePublicId(),
                ownerAuthId,
                deviceType,
                testContext.publicKey()
            )
        );
    }

}
