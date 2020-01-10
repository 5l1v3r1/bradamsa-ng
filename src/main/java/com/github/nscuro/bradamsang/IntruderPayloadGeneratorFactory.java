package com.github.nscuro.bradamsang;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.io.CommandExecutor;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import com.github.nscuro.bradamsang.radamsa.Radamsa;

public final class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final BurpExtensionSettingsProvider extensionSettings;

    private final BurpLogger burpLogger;

    IntruderPayloadGeneratorFactory(final BurpExtensionSettingsProvider extensionSettings, final BurpLogger burpLogger) {
        this.extensionSettings = extensionSettings;
        this.burpLogger = burpLogger;
    }

    @Override
    public String getGeneratorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(final IIntruderAttack attack) {
        final IntruderAttackSettings attackSettings = extensionSettings.buildIntruderAttackSettings();

        final CommandExecutor commandExecutor;

        if (attackSettings.isWslModeEnabled()) {
            commandExecutor = attackSettings.getWslDistroName()
                    .map(distroName -> new WslCommandExecutor(new NativeCommandExecutor(), distroName))
                    .orElseThrow(() -> new BurpExtensionConfigurationException("WSL mode enabled, but no distro selected"));
        } else {
            commandExecutor = new NativeCommandExecutor();
        }

        final Radamsa radamsa = new Radamsa(commandExecutor, extensionSettings.getRadamsaPath()
                .orElseThrow(() -> new BurpExtensionConfigurationException("No path to Radamsa executable provided")));

        return new IntruderPayloadGenerator(burpLogger, attackSettings, radamsa);
    }

}
