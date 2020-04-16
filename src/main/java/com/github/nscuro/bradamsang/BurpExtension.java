package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.util.BurpLogger;

public final class BurpExtension {

    static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final var burpLogger = new BurpLogger(extenderCallbacks);

        final var extensionSettingsTab = new ExtensionSettingsTab(new NativeCommandExecutor(), burpLogger);
        extenderCallbacks.addSuiteTab(extensionSettingsTab);

        final var payloadGeneratorFactory = new IntruderPayloadGeneratorFactory(extensionSettingsTab, burpLogger);
        extenderCallbacks.registerIntruderPayloadGeneratorFactory(payloadGeneratorFactory);

        final var payloadProcessor = new IntruderPayloadProcessor(null, burpLogger);
        extenderCallbacks.registerIntruderPayloadProcessor(payloadProcessor);
    }

}
