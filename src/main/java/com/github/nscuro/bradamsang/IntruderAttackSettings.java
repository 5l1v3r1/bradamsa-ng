package com.github.nscuro.bradamsang;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

final class IntruderAttackSettings {

    private final int payloadLimit;

    private final List<Path> samplePaths;

    private final boolean wslModeEnabled;

    private final String wslDistroName;

    IntruderAttackSettings(final int payloadLimit, final List<Path> samplePaths,
                           final boolean wslModeEnabled, final String wslDistroName) {
        this.payloadLimit = payloadLimit;
        this.samplePaths = samplePaths;
        this.wslModeEnabled = wslModeEnabled;
        this.wslDistroName = wslDistroName;
    }

    int getPayloadLimit() {
        return payloadLimit;
    }

    public List<Path> getSamplePaths() {
        return Optional.ofNullable(samplePaths)
                .orElseGet(Collections::emptyList);
    }

    boolean isWslModeEnabled() {
        return wslModeEnabled;
    }

    Optional<String> getWslDistroName() {
        return Optional.ofNullable(wslDistroName);
    }

    @Override
    public String toString() {
        return "IntruderAttackSettings{" +
                "payloadLimit=" + payloadLimit +
                ", wslModeEnabled=" + wslModeEnabled +
                ", wslDistroName='" + wslDistroName + '\'' +
                '}';
    }

}
