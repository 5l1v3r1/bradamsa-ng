package com.github.nscuro.bradamsang;

import com.github.nscuro.bradamsang.intruder.IntruderAttackSettings;

import java.util.List;
import java.util.Optional;

public interface ExtensionSettingsProvider {

    Optional<String> getRadamsaExecutablePath();

    int getPayloadCount();

    List<String> getSamplePaths();

    boolean isWslModeEnabled();

    Optional<String> getWslDistributionName();

    default IntruderAttackSettings buildIntruderAttackSettings() {
        return new IntruderAttackSettings(getPayloadCount(), getSamplePaths(),
                isWslModeEnabled(), getWslDistributionName().orElse(null));
    }

}
