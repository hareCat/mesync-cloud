package com.iplion.mesync.cloud.security.pipeline;

import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.security.request.UnregisteredDeviceAuthRequest;
import com.iplion.mesync.cloud.security.request.RegisteredDeviceAuthRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mock;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;

public class AuthPipelineServiceTest extends BaseUnitTest {
    @Mock
    RedisAuthChecker redisAuthChecker;

    @Mock
    DeviceAuthChecker deviceAuthChecker;

    @Mock
    AuthDataLoader authDataLoader;

    @Mock
    SignatureVerifier signatureVerifier;

    AuthPipelineService authPipelineService;

    @BeforeEach
    void setUp() {
        authPipelineService = new AuthPipelineService(
            redisAuthChecker,
            deviceAuthChecker,
            authDataLoader,
            signatureVerifier
        );
    }

    @Test
    public void verifyUnregisteredDeviceRequest_shouldRunPipelineStepsInOrder_whenRequestValid() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var request = TestPipelineFactory.unregisteredDeviceAuthRequest(testContext);

        doAnswer(invocation -> {
            AuthPipelineContext<UnregisteredDeviceAuthRequest> authPipelineContext = invocation.getArgument(0);
            authPipelineContext.setJwtUserData(testContext.jwtUserData());
            return null;
        }).when(authDataLoader).loadJwtData(any());
        doAnswer(invocation -> {
            AuthPipelineContext<UnregisteredDeviceAuthRequest> authPipelineContext = invocation.getArgument(0);
            authPipelineContext.setAuthData(testContext.authData());
            return null;
        }).when(authDataLoader).loadUnregisteredDeviceAuthData(any());

        AuthPipelineResult result = authPipelineService.verifyUnregisteredDeviceRequest(request);

        InOrder inOrder = inOrder(authDataLoader, redisAuthChecker, signatureVerifier);
        inOrder.verify(authDataLoader).loadJwtData(any());
        inOrder.verify(redisAuthChecker).unregisteredDeviceSecurityCheck(any());
        inOrder.verify(authDataLoader).loadUnregisteredDeviceAuthData(any());
        inOrder.verify(signatureVerifier).verifySignature(any());

        assertThat(result.jwtUserData()).isEqualTo(testContext.jwtUserData());
        assertThat(result.authData()).isEqualTo(testContext.authData());
    }

    @Test
    public void verifyDeviceManagerRequest_shouldRunPipelineStepsInOrder_whenRequestValid() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var request = TestPipelineFactory.registeredDeviceAuthRequest(testContext);

        mockRegisteredAuthDataLoad(testContext);

        var result = authPipelineService.verifyDeviceManagerRequest(request);

        InOrder inOrder = inOrder(authDataLoader, redisAuthChecker, deviceAuthChecker, signatureVerifier);
        inOrder.verify(authDataLoader).loadJwtData(any());
        inOrder.verify(redisAuthChecker).registeredDeviceSecurityCheck(any());
        inOrder.verify(authDataLoader).loadRegisteredDeviceAuthData(any());
        inOrder.verify(deviceAuthChecker).deviceOwnerCheck(any());
        inOrder.verify(signatureVerifier).verifySignature(any());

        assertThat(result).isEqualTo(testContext.authData());
    }

    @Test
    public void verifyMessagingRequest_shouldRunPipelineStepsInOrder_whenRequestValid() throws Exception {
        var testContext = TestPipelineFactory.testContext();
        var request = TestPipelineFactory.registeredDeviceAuthRequest(testContext);

        mockRegisteredAuthDataLoad(testContext);

        var result = authPipelineService.verifyMessagingRequest(request);

        InOrder inOrder = inOrder(authDataLoader, redisAuthChecker, deviceAuthChecker, signatureVerifier);
        inOrder.verify(authDataLoader).loadJwtData(any());
        inOrder.verify(redisAuthChecker).registeredDeviceSecurityCheck(any());
        inOrder.verify(authDataLoader).loadRegisteredDeviceAuthData(any());
        inOrder.verify(deviceAuthChecker).deviceOwnerCheck(any());
        inOrder.verify(deviceAuthChecker).deviceTypeCheck(any());
        inOrder.verify(signatureVerifier).verifySignature(any());

        assertThat(result).isEqualTo(testContext.authData());
    }

    private void mockRegisteredAuthDataLoad(TestPipelineFactory.TestContext testContext) {
        doAnswer(invocation -> {
            AuthPipelineContext<RegisteredDeviceAuthRequest> authPipelineContext = invocation.getArgument(0);
            authPipelineContext.setAuthData(testContext.authData());
            return null;
        }).when(authDataLoader).loadRegisteredDeviceAuthData(any());
    }

}
