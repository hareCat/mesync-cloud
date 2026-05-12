package com.iplion.mesync.cloud.security.auth;

import com.iplion.mesync.cloud.model.DeviceAuthData;
import com.iplion.mesync.cloud.model.JwtUserData;
import lombok.Data;

import java.security.PublicKey;
import java.util.UUID;

@Data
public class AuthPipelineContext<T extends AuthRequest> {
    private final T request;
    JwtUserData jwtUserData;
    UUID securitySubjectId;
    PublicKey publicKey;
    DeviceAuthData deviceAuthData;

}
