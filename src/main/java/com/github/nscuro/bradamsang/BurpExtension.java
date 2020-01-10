package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderPayloadGeneratorFactory;
import burp.IIntruderPayloadProcessor;

public final class BurpExtension {

    static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final BurpLogger burpLogger = new BurpLogger(extenderCallbacks);
        final BurpExtensionSettingsProvider extensionSettings = new BurpExtensionSettingsProvider(extenderCallbacks);

        final IIntruderPayloadGeneratorFactory payloadGeneratorFactory =
                new IntruderPayloadGeneratorFactory(extensionSettings, burpLogger);
        extenderCallbacks.registerIntruderPayloadGeneratorFactory(payloadGeneratorFactory);

        final IIntruderPayloadProcessor payloadProcessor = new IntruderPayloadProcessor(null, burpLogger);
        extenderCallbacks.registerIntruderPayloadProcessor(payloadProcessor);
    }

}
