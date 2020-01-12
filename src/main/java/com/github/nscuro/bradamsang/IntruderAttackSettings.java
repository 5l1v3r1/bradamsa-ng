package com.github.nscuro.bradamsang;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

final class IntruderAttackSettings {

    private final int payloadCount;

    private final List<String> samplePaths;

    private final boolean wslModeEnabled;

    private final String wslDistribution;

    IntruderAttackSettings(final int payloadCount, final List<String> samplePaths,
                           final boolean wslModeEnabled, final String wslDistribution) {
        this.payloadCount = payloadCount;
        this.samplePaths = samplePaths;
        this.wslModeEnabled = wslModeEnabled;
        this.wslDistribution = wslDistribution;
    }

    int getPayloadCount() {
        return payloadCount;
    }

    public List<String> getSamplePaths() {
        return Optional.ofNullable(samplePaths)
                .orElseGet(Collections::emptyList);
    }

    boolean isWslModeEnabled() {
        return wslModeEnabled;
    }

    Optional<String> getWslDistribution() {
        return Optional.ofNullable(wslDistribution);
    }

    @Override
    public String toString() {
        return "IntruderAttackSettings{" +
                "payloadCount=" + payloadCount +
                ", samplePaths=" + samplePaths +
                ", wslModeEnabled=" + wslModeEnabled +
                ", wslDistroName='" + wslDistribution + '\'' +
                '}';
    }

}
