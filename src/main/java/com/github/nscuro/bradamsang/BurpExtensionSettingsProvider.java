package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import org.apache.commons.lang3.math.NumberUtils;

import java.util.Optional;

public final class BurpExtensionSettingsProvider {

    private static final String SETTING_RADAMSA_PATH = "BRADAMSANG_RADAMSA_PATH";
    private static final String SETTING_PAYLOAD_LIMIT = "BRADAMSANG_PAYLOAD_LIMIT";
    private static final String SETTING_WSL_MODE_ENABLED = "BRADAMSANG_WSL_MODE_ENABLED";
    private static final String SETTING_WSL_DISTRO_NAME = "BRADAMSANG_WSL_DISTRO_NAME";

    private final IBurpExtenderCallbacks extenderCallbacks;

    BurpExtensionSettingsProvider(final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
    }

    public void setRadamsaPath(final String radamsaPath) {
        extenderCallbacks.saveExtensionSetting(SETTING_RADAMSA_PATH, radamsaPath);
    }

    public Optional<String> getRadamsaPath() {
        return Optional.ofNullable(extenderCallbacks.loadExtensionSetting(SETTING_RADAMSA_PATH));
    }

    public int getPayloadLimit() {
        return Optional.ofNullable(extenderCallbacks.loadExtensionSetting(SETTING_PAYLOAD_LIMIT))
                .filter(NumberUtils::isParsable)
                .map(Integer::parseInt)
                .orElse(-1);
    }

    public boolean isWslModeEnabled() {
        return Optional.ofNullable(extenderCallbacks.loadExtensionSetting(SETTING_WSL_MODE_ENABLED))
                .map(Boolean::parseBoolean)
                .orElse(false);
    }

    public Optional<String> getWslDistroName() {
        return Optional.ofNullable(extenderCallbacks.loadExtensionSetting(SETTING_WSL_DISTRO_NAME));
    }

    public IntruderAttackSettings buildIntruderAttackSettings() {
        return new IntruderAttackSettings(getPayloadLimit(), isWslModeEnabled(), getWslDistroName().orElse(null));
    }

}
