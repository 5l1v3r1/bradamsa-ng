package com.github.nscuro.bradamsang;

import burp.IIntruderPayloadProcessor;
import org.apache.commons.lang3.NotImplementedException;

public final class IntruderPayloadProcessor implements IIntruderPayloadProcessor {

    @Override
    public String getProcessorName() {
        return BurpExtension.EXTENSION_NAME;
    }

    @Override
    public byte[] processPayload(final byte[] currentPayload, final byte[] originalPayload, final byte[] baseValue) {
        throw new NotImplementedException("Payload Processor is not yet implemented");
    }

}
