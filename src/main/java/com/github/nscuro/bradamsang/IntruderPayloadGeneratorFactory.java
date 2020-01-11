package com.github.nscuro.bradamsang;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.io.CommandExecutor;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.io.WslCommandExecutor;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.util.BurpLogger;

public final class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final ExtensionSettingsProvider extensionSettingsProvider;

    private final BurpLogger burpLogger;

    IntruderPayloadGeneratorFactory(final ExtensionSettingsProvider extensionSettingsProvider, final BurpLogger burpLogger) {
        this.extensionSettingsProvider = extensionSettingsProvider;
        this.burpLogger = burpLogger;
    }

    @Override
    public String getGeneratorName() {
        return BradamsaNgExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(final IIntruderAttack attack) {
        if (!extensionSettingsProvider.getRadamsaExecutablePath().isPresent()) {
            throw new ExtensionConfigurationException("");
        }

        final IntruderAttackSettings attackSettings = extensionSettingsProvider.buildIntruderAttackSettings();

        if (attackSettings.isWslModeEnabled() && !attackSettings.getWslDistribution().isPresent()) {
            throw new ExtensionConfigurationException("");
        }

        final CommandExecutor commandExecutor;

        if (attackSettings.isWslModeEnabled()) {
            commandExecutor = attackSettings.getWslDistribution()
                    .map(distroName -> new WslCommandExecutor(new NativeCommandExecutor(), distroName))
                    .orElseThrow(() -> new ExtensionConfigurationException("WSL mode enabled, but no distro selected"));
        } else {
            commandExecutor = new NativeCommandExecutor();
        }

        final Radamsa radamsa = new Radamsa(commandExecutor, extensionSettingsProvider.getRadamsaExecutablePath()
                .orElseThrow(() -> new ExtensionConfigurationException("No path to Radamsa executable provided")));

        burpLogger.info("Launching Intruder attack with " + attackSettings);

        return new IntruderPayloadGenerator(burpLogger, attackSettings, radamsa);
    }

}
