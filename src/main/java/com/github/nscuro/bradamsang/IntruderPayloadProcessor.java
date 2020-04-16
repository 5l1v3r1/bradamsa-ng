package com.github.nscuro.bradamsang;

import burp.IIntruderPayloadProcessor;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.radamsa.RadamsaParameters;
import com.github.nscuro.bradamsang.util.BurpLogger;

import java.io.IOException;

public final class IntruderPayloadProcessor implements IIntruderPayloadProcessor {

    private final Radamsa radamsa;
    private final BurpLogger burpLogger;

    IntruderPayloadProcessor(final Radamsa radamsa, final BurpLogger burpLogger) {
        this.radamsa = radamsa;
        this.burpLogger = burpLogger;
    }

    @Override
    public String getProcessorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public byte[] processPayload(final byte[] currentPayload, final byte[] originalPayload, final byte[] baseValue) {
        if (currentPayload == null) {
            throw new IllegalArgumentException("No current payload provided");
        }

        final var radamsaParameters = new RadamsaParameters(currentPayload, null);

        final byte[] fuzzedValue;
        try {
            fuzzedValue = radamsa.fuzz(radamsaParameters);
        } catch (IOException e) {
            burpLogger.error(e);
            return currentPayload;
        }

        return fuzzedValue;
    }

}
