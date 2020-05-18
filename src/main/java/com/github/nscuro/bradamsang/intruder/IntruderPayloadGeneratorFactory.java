package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.ExtensionConfigurationException;
import com.github.nscuro.bradamsang.ExtensionSettingsProvider;
import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.NativeCommandExecutor;
import com.github.nscuro.bradamsang.command.WslCommandExecutor;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.util.BurpLogger;

public final class IntruderPayloadGeneratorFactory implements IIntruderPayloadGeneratorFactory {

    private final ExtensionSettingsProvider extensionSettingsProvider;
    private final BurpLogger burpLogger;

    public IntruderPayloadGeneratorFactory(final ExtensionSettingsProvider extensionSettingsProvider, final BurpLogger burpLogger) {
        this.extensionSettingsProvider = extensionSettingsProvider;
        this.burpLogger = burpLogger;
    }

    @Override
    public String getGeneratorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(final IIntruderAttack attack) {
        if (extensionSettingsProvider.getRadamsaExecutablePath().isEmpty()) {
            throw new ExtensionConfigurationException("No Radamsa executable path provided");
        }

        final IntruderAttackSettings attackSettings = extensionSettingsProvider.buildIntruderAttackSettings();

        final CommandExecutor commandExecutor;
        if (attackSettings.isWslModeEnabled()) {
            commandExecutor = attackSettings.getWslDistribution()
                    .map(distroName -> new WslCommandExecutor(new NativeCommandExecutor(), distroName))
                    .orElseThrow(() -> new ExtensionConfigurationException("WSL mode enabled, but no distro selected"));
        } else {
            commandExecutor = new NativeCommandExecutor();
        }

        final var radamsa = new Radamsa(commandExecutor, extensionSettingsProvider.getRadamsaExecutablePath()
                .orElseThrow(() -> new ExtensionConfigurationException("No path to Radamsa executable provided")));

        burpLogger.info("Launching Intruder attack with " + attackSettings);

        return new IntruderPayloadGenerator(burpLogger, attackSettings, radamsa);
    }

}
