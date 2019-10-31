package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.io.CommandExecutor;
import com.github.nscuro.bradamsang.io.ExecutionResult;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

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
            radamsaCommand.addAll(Arrays.asList("-g", "stdin"));

            executionResult = commandExecutor.execute(radamsaCommand, parameters.getSample().get());
        } else {
            radamsaCommand.addAll(Arrays.asList("-g", "file"));

            radamsaCommand.addAll(parameters.getSamplePaths().stream()
                    .map(Path::toAbsolutePath)
                    .map(Path::toString)
                    .collect(Collectors.toList()));

            executionResult = commandExecutor.execute(radamsaCommand);
        }

        if (executionResult.getExitCode() != 0) {
            throw new IOException(format("radamsa execution %s appears to have failed.\n%s", radamsaPath, executionResult));
        }

        return executionResult.getStdoutOutput()
                .map(String::getBytes)
                .orElseThrow(IllegalStateException::new);
    }

    public String getVersion() throws IOException {
        return commandExecutor.execute(Arrays.asList(radamsaPath, "-V")).getStdoutOutput()
                .map(String::trim)
                .map(output -> output.split(" ", 1))
                .filter(outputParts -> outputParts.length == 2)
                .map(outputParts -> outputParts[1])
                .orElseThrow(IllegalStateException::new);
    }

}
