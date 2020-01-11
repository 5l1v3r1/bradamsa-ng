package burp;

import com.github.nscuro.bradamsang.BradamsaNgExtension;

public final class BurpExtender implements IBurpExtender {

    private final BradamsaNgExtension bradamsaNgExtension;

    BurpExtender(final BradamsaNgExtension bradamsaNgExtension) {
        this.bradamsaNgExtension = bradamsaNgExtension;
    }

    public BurpExtender() {
        this(new BradamsaNgExtension());
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks extenderCallbacks) {
        bradamsaNgExtension.registerExtension(extenderCallbacks);
    }

}
