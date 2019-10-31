package com.github.nscuro.bradamsang;

import java.util.Optional;

final class IntruderAttackSettings {

    private final int payloadLimit;

    private final boolean wslModeEnabled;

    private final String wslDistroName;

    IntruderAttackSettings(final int payloadLimit, final boolean wslModeEnabled, final String wslDistroName) {
        this.payloadLimit = payloadLimit;
        this.wslModeEnabled = wslModeEnabled;
        this.wslDistroName = wslDistroName;
    }

    int getPayloadLimit() {
        return payloadLimit;
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
