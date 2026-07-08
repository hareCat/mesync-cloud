package com.iplion.mesync.cloud.controller.dto.device;

import java.util.List;

public record DeviceListResponseDto(
    List<DeviceListItemDto> devices
) {
}
