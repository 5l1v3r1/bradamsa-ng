package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import com.github.nscuro.bradamsang.intruder.IntruderPayloadGeneratorFactory;
import com.github.nscuro.bradamsang.intruder.IntruderPayloadProcessorFactory;
import com.github.nscuro.bradamsang.command.NativeCommandExecutor;
import com.github.nscuro.bradamsang.ui.ExtensionSettingsTab;
import com.github.nscuro.bradamsang.util.BurpLogger;

public final class BurpExtension {

    public static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final var burpLogger = new BurpLogger(extenderCallbacks);

        final var settingsTab = new ExtensionSettingsTab(new NativeCommandExecutor(), burpLogger);
        extenderCallbacks.addSuiteTab(settingsTab);

        final var payloadGeneratorFactory = new IntruderPayloadGeneratorFactory(settingsTab, burpLogger);
        extenderCallbacks.registerIntruderPayloadGeneratorFactory(payloadGeneratorFactory);

        final var payloadProcessorFactory = new IntruderPayloadProcessorFactory(settingsTab, burpLogger);
        extenderCallbacks.registerIntruderPayloadProcessor(payloadProcessorFactory);
    }

}
