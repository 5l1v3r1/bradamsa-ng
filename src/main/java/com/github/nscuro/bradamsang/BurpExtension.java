package com.github.nscuro.bradamsang;

import burp.IBurpExtenderCallbacks;

public final class BurpExtension {

    private static final String EXTENSION_NAME = "bradamsa-ng";

    public void registerExtension(final IBurpExtenderCallbacks extenderCallbacks) {
        extenderCallbacks.setExtensionName(EXTENSION_NAME);
    }

}
