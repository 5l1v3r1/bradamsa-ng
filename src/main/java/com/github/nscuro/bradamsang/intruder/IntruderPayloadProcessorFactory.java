package com.github.nscuro.bradamsang.intruder;

import burp.IIntruderPayloadProcessor;
import com.github.nscuro.bradamsang.BurpExtension;
import com.github.nscuro.bradamsang.ExtensionSettingsProvider;
import com.github.nscuro.bradamsang.util.BurpLogger;

import java.util.Objects;

/**
 * An {@link IIntruderPayloadProcessor} that acts as a factory for {@link IntruderPayloadProcessor}.
 */
public final class IntruderPayloadProcessorFactory implements IIntruderPayloadProcessor {

    private final ExtensionSettingsProvider settingsProvider;
    private final BurpLogger burpLogger;

    private volatile IntruderPayloadProcessor payloadProcessor;
    private int currentSettingsHashCode;

    public IntruderPayloadProcessorFactory(final ExtensionSettingsProvider settingsProvider,
                                           final BurpLogger burpLogger) {
        this.settingsProvider = settingsProvider;
        this.burpLogger = burpLogger;
    }

    @Override
    public String getProcessorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        return getPayloadProcessor().processPayload(currentPayload, originalPayload, baseValue);
    }

    private IIntruderPayloadProcessor getPayloadProcessor() {
        if (payloadProcessor == null) {
            synchronized (this) {
                if (payloadProcessor == null) {
                    payloadProcessor = new IntruderPayloadProcessor(null, burpLogger);
                    currentSettingsHashCode = Objects.hash(settingsProvider.getRadamsaExecutablePath(), settingsProvider.getWslDistributionName());
                    return payloadProcessor;
                }
            }
        }

        final int settingsHashCode = Objects.hash(settingsProvider.getRadamsaExecutablePath(), settingsProvider.getWslDistributionName());
        if (settingsHashCode != currentSettingsHashCode) {
            payloadProcessor = new IntruderPayloadProcessor(null, burpLogger);
            currentSettingsHashCode = settingsHashCode;
        }

        return payloadProcessor;
    }

}
