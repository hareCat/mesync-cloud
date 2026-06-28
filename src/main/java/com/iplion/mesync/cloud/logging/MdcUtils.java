package com.iplion.mesync.cloud.logging;

import com.iplion.mesync.cloud.model.JwtUserData;
import com.iplion.mesync.cloud.security.cache.AuthData;
import com.iplion.mesync.cloud.security.cache.DeviceAuthData;
import com.iplion.mesync.cloud.security.cache.UserAuthData;
import org.slf4j.MDC;

public final class MdcUtils {
    private MdcUtils() {}

    public static void putJwtUserData(JwtUserData jwtUserData) {
        if (jwtUserData == null) {
            return;
        }

        put(MdcKeys.JWT_AUTH_ID, jwtUserData.authId());
        put(MdcKeys.CLIENT_ID, jwtUserData.clientId());
    }

    public static void putAuthData(AuthData authData) {
        if (authData == null) {
            return;
        }


        putUserAuthData(authData.userAuthData());
        putDeviceAuthData(authData.deviceAuthData());
    }

    private static void putUserAuthData(UserAuthData userAuthData) {
        if (userAuthData == null) {
            return;
        }

        put(MdcKeys.USER_ID, userAuthData.id());
        put(MdcKeys.USER_AUTH_ID, userAuthData.authId());
    }

    private static void putDeviceAuthData(DeviceAuthData deviceAuthData) {
        if (deviceAuthData == null) {
            return;
        }

        put(MdcKeys.DEVICE_ID, deviceAuthData.id());
        put(MdcKeys.DEVICE_PUBLIC_ID, deviceAuthData.publicId());
        put(MdcKeys.DEVICE_TYPE, deviceAuthData.deviceType());
    }

    public static void put(String key, Object value) {
        if (value != null) {
            MDC.put(key, value.toString());
        }
    }
}
