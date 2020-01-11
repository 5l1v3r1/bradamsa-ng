package com.github.nscuro.bradamsang;

import java.util.Optional;

public interface ExtensionSettingsProvider {

    Optional<String> getRadamsaExecutablePath();

    int getPayloadCount();

    boolean isWslModeEnabled();

    Optional<String> getWslDistributionName();

    default IntruderAttackSettings buildIntruderAttackSettings() {
        return new IntruderAttackSettings(getPayloadCount(), null, isWslModeEnabled(),
                getWslDistributionName().orElse(null));
    }

}
