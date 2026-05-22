package com.iplion.mesync.cloud.controller.dto;

import java.util.UUID;

public interface SignedRequest {

    UUID nonce();

    String base64Signature();

}
