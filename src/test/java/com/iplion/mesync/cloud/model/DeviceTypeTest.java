package com.iplion.mesync.cloud.model;

import com.iplion.mesync.cloud.error.InvalidDeviceTypeException;
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
            .isInstanceOf(InvalidDeviceTypeException.class)
            .hasMessageContaining("ClientId is null or blank");
    }

    @Test
    void fromClientId_shouldThrowWhenClientIdIsUnknown() {
        assertThatThrownBy(() -> DeviceType.fromClientId("unknown-client"))
            .isInstanceOf(InvalidDeviceTypeException.class)
            .hasMessageContaining("Unknown clientId");
    }
}
