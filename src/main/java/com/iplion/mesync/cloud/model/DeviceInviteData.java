package com.iplion.mesync.cloud.model;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class DeviceInviteData {
    private String base64EncryptionPublicKey;
    private String base64SigningPublicKey;
    private String base64EncryptedMasterKey;
    private Integer keyVersion;
    private DeviceType deviceType;

}
