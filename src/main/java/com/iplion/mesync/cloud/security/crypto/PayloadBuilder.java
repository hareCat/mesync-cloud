package com.iplion.mesync.cloud.security.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class PayloadBuilder {

    private static final String VERSION = "v1";

    private PayloadBuilder() {}

    public static byte[] build(String... lines) {
        Objects.requireNonNull(lines);

        return Stream.concat(
                Stream.of(VERSION),
                Arrays.stream(lines)
            )
            .collect(Collectors.joining("\n"))
            .getBytes(StandardCharsets.UTF_8);
    }

}