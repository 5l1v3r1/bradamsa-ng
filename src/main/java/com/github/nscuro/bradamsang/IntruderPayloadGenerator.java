package com.github.nscuro.bradamsang;

import burp.IIntruderPayloadGenerator;
import com.github.nscuro.bradamsang.radamsa.Radamsa;
import com.github.nscuro.bradamsang.radamsa.RadamsaParameters;

import java.io.IOException;

public final class IntruderPayloadGenerator implements IIntruderPayloadGenerator {

    private final BurpLogger burpLogger;

    private final IntruderAttackSettings attackSettings;

    private final Radamsa radamsa;

    private int payloadsGenerated;

    IntruderPayloadGenerator(final BurpLogger burpLogger,
                             final IntruderAttackSettings attackSettings,
                             final Radamsa radamsa) {
        this.burpLogger = burpLogger;
        this.attackSettings = attackSettings;
        this.radamsa = radamsa;
    }

    @Override
    public boolean hasMorePayloads() {
        if (attackSettings.getPayloadLimit() < 0) {
            return true;
        }

        return payloadsGenerated < attackSettings.getPayloadLimit();
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        if (baseValue == null) {
            throw new IllegalArgumentException("No baseValue provided");
        }

        final RadamsaParameters radamsaParameters = new RadamsaParameters(baseValue, null);

        final byte[] fuzzedValue;
        try {
            fuzzedValue = radamsa.fuzz(radamsaParameters);
        } catch (IOException e) {
            burpLogger.error(e);
            return null;
        }

        payloadsGenerated++;
        return fuzzedValue;
    }

    @Override
    public void reset() {
        payloadsGenerated = 0;
    }

}
