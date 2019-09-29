package com.github.nscuro.bradamsang.radamsa;

public final class RadamsaException extends Exception {

    RadamsaException(final String message) {
        super(message);
    }

    RadamsaException(final Throwable cause) {
        super(cause);
    }

    RadamsaException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
