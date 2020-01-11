package com.github.nscuro.bradamsang.util;

import burp.IBurpExtenderCallbacks;

import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import static java.lang.String.format;

public final class BurpLogger {

    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final IBurpExtenderCallbacks extenderCallbacks;

    public BurpLogger(final IBurpExtenderCallbacks extenderCallbacks) {
        this.extenderCallbacks = extenderCallbacks;
    }

    public void info(final String message) {
        extenderCallbacks.printOutput(format("[INFO] %s %s", getTimestamp(), message));
    }

    public void error(final String message) {
        extenderCallbacks.printError(format("[ERROR] %s %s", getTimestamp(), message));
    }

    public void error(final Throwable throwable) {
        try (final PrintWriter printWriter = new PrintWriter(extenderCallbacks.getStderr())) {
            throwable.printStackTrace(printWriter);
        }
    }

    public void error(final String message, final Throwable throwable) {
        error(message);
        error(throwable);
    }

    public void warn(final String message) {
        extenderCallbacks.printOutput(format("[WARN] %s %s", getTimestamp(), message));
    }

    private String getTimestamp() {
        return LocalDateTime.now().format(DATE_TIME_FORMATTER);
    }

}
