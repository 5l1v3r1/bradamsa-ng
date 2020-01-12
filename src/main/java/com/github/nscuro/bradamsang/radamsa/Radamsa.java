package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.io.CommandExecutor;
import com.github.nscuro.bradamsang.io.ExecutionResult;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


import static java.lang.String.format;

public final class Radamsa {

    private final CommandExecutor commandExecutor;

    private final String radamsaPath;

    public Radamsa(final CommandExecutor commandExecutor, final String radamsaPath) {
        this.commandExecutor = commandExecutor;
        this.radamsaPath = radamsaPath;
    }

    public byte[] fuzz(final RadamsaParameters parameters) throws IOException {
        if (parameters == null) {
            throw new IllegalArgumentException("No parameters provided");
        } else if (!parameters.getSample().isPresent() && parameters.getSamplePaths().isEmpty()) {
            throw new IllegalArgumentException("No sample data provided");
        }

        final List<String> radamsaCommand = new ArrayList<>();
        radamsaCommand.add(radamsaPath);

        final ExecutionResult executionResult;
        if (parameters.getSample().isPresent()) {
            executionResult = commandExecutor.execute(radamsaCommand, parameters.getSample().get());
        } else {
            radamsaCommand.add("--recursive");
            radamsaCommand.addAll(parameters.getSamplePaths());

            executionResult = commandExecutor.execute(radamsaCommand);
        }

        if (executionResult.getExitCode() != 0) {
            throw new RadamsaExecutionFailedException(radamsaCommand, executionResult);
        }

        return executionResult.getStdoutOutput()
                .map(String::getBytes)
                .orElseThrow(IllegalStateException::new);
    }

    public String getVersion() throws IOException {
        final List<String> command = Arrays.asList(radamsaPath, "-V");
        final ExecutionResult executionResult = commandExecutor.execute(command);

        if (executionResult.getExitCode() != 0) {
            throw new RadamsaExecutionFailedException(command, executionResult);
        }

        return executionResult.getStdoutOutput()
                .map(String::trim)
                .map(output -> output.split(" ", 1))
                .filter(outputParts -> outputParts.length == 2)
                .map(outputParts -> outputParts[1])
                .orElseThrow(() -> new RadamsaException(format("Missing or unexpected output for command %s", command)));
    }

}
