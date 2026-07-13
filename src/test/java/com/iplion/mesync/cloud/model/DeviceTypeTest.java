package com.iplion.mesync.cloud.model;

import com.iplion.mesync.cloud.error.api.ApiErrorCode;
import com.iplion.mesync.cloud.error.api.InvalidDeviceTypeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DeviceTypeTest {

    @Test
    void fromClientId_shouldReturnDeviceTypeIgnoringCaseAndWhitespace() {
        assertThat(DeviceType.fromClientId("  MeSync-Browser  ")).isEqualTo(DeviceType.BROWSER);
    }

    @ParameterizedTest
    @ValueSource(strings = {"   ", "unknown-client"})
    void fromClientId_shouldThrowWhenClientIdIsInvalid(String clientId) {
        assertThatThrownBy(() -> DeviceType.fromClientId(clientId))
            .isInstanceOfSatisfying(InvalidDeviceTypeException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.DEVICE_INVALID_TYPE)
            );
    }
}
