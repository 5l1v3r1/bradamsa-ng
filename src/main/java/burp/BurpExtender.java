package burp;

import com.github.nscuro.bradamsang.BurpExtension;

public final class BurpExtender implements IBurpExtender {

    private final BurpExtension burpExtension;

    BurpExtender(final BurpExtension burpExtension) {
        this.burpExtension = burpExtension;
    }

    /**
     * Default constructor used by Burp to instantiate the extension.
     */
    @SuppressWarnings("unused")
    public BurpExtender() {
        this(new BurpExtension());
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks extenderCallbacks) {
        burpExtension.registerExtension(extenderCallbacks);
    }

}
