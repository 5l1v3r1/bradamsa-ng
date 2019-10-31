package com.github.nscuro.bradamsang.io;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class WslCommandExecutor extends CommandExecutor {

    private final String distroName;

    public WslCommandExecutor(final String distroName) {
        this.distroName = distroName;
    }

    @Override
    public ExecutionResult execute(List<String> command, byte[] inputData) throws IOException {
        final List<String> wslCommand = new ArrayList<>();

        wslCommand.addAll(Arrays.asList("wsl", "-d", distroName, "-e"));
        wslCommand.addAll(command);

        return super.execute(wslCommand, inputData);
    }

}
