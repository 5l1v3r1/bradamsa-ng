package com.github.nscuro.bradamsang.io;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public final class WslCommandExecutor implements CommandExecutor {

    private final NativeCommandExecutor nativeCommandExecutor;
    private final String distroName;

    public WslCommandExecutor(final NativeCommandExecutor nativeCommandExecutor,
                              final String distroName) {
        this.nativeCommandExecutor = Objects.requireNonNull(nativeCommandExecutor);
        this.distroName = Objects.requireNonNull(StringUtils.trimToNull(distroName));
    }

    @Override
    public ExecutionResult execute(final List<String> command, final byte[] inputData) throws IOException {
        final var wslCommand = new ArrayList<String>();

        wslCommand.addAll(Arrays.asList("wsl", "-d", distroName, "-e"));
        wslCommand.addAll(command);

        return nativeCommandExecutor.execute(wslCommand, inputData);
    }

}
