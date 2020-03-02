package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;
import burp.IIntruderPayloadGeneratorFactory;
import burp.IIntruderPayloadProcessor;
import com.github.nscuro.bradamsang.io.NativeCommandExecutor;
import com.github.nscuro.bradamsang.util.BurpLogger;

public final class BurpExtension {

    static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);

        final BurpLogger burpLogger = new BurpLogger(extenderCallbacks);

        final ExtensionSettingsTab extensionSettingsTab = new ExtensionSettingsTab(new NativeCommandExecutor(), burpLogger);
        extenderCallbacks.addSuiteTab(extensionSettingsTab);

        final IIntruderPayloadGeneratorFactory payloadGeneratorFactory =
                new IntruderPayloadGeneratorFactory(extensionSettingsTab, burpLogger);
        extenderCallbacks.registerIntruderPayloadGeneratorFactory(payloadGeneratorFactory);

        final IIntruderPayloadProcessor payloadProcessor = new IntruderPayloadProcessor(null, burpLogger);
        extenderCallbacks.registerIntruderPayloadProcessor(payloadProcessor);
    }

}
