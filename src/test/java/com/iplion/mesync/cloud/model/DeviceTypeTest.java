package com.iplion.mesync.cloud.model;

import com.iplion.mesync.cloud.error.api.ApiErrorCode;
import com.iplion.mesync.cloud.error.api.InvalidDeviceTypeException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DeviceTypeTest {

    @Test
    void fromClientId_shouldReturnDeviceTypeIgnoringCaseAndWhitespace() {
        assertThat(DeviceType.fromClientId("  MeSync-Browser  ")).isEqualTo(DeviceType.BROWSER);
    }

    @Test
    void fromClientId_shouldThrowWhenClientIdIsBlank() {
        assertThatThrownBy(() -> DeviceType.fromClientId("   "))
            .isInstanceOfSatisfying(InvalidDeviceTypeException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.DEVICE_INVALID_TYPE)
            );
    }

    @Test
    void fromClientId_shouldThrowWhenClientIdIsUnknown() {
        assertThatThrownBy(() -> DeviceType.fromClientId("unknown-client"))
            .isInstanceOfSatisfying(InvalidDeviceTypeException.class, e ->
                assertThat(e.getErrorCode()).isEqualTo(ApiErrorCode.DEVICE_INVALID_TYPE)
            );
    }
}
