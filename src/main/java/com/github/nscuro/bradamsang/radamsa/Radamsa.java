package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.ExecutionResult;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class Radamsa {

    private final CommandExecutor commandExecutor;
    private final String radamsaPath;

    /**
     * @param commandExecutor The {@link CommandExecutor} to use
     * @param radamsaPath     Path to the Radamsa executable
     * @throws NullPointerException When either {@code commandExecutor} or {@code radamsaPath} are {@code null}
     */
    public Radamsa(final CommandExecutor commandExecutor, final String radamsaPath) {
        this.commandExecutor = Objects.requireNonNull(commandExecutor);
        this.radamsaPath = Objects.requireNonNull(StringUtils.trimToNull(radamsaPath));
    }

    /**
     * Generate a test case based on a given sample or one or more sample files.
     * <p>
     * When both {@link RadamsaParameters#getSample()} and {@link RadamsaParameters#getSamplePaths()}
     * are provided, {@link RadamsaParameters#getSample()} takes precedence.
     *
     * @param parameters A {@link RadamsaParameters} object
     * @return The generated test case as byte array
     * @throws RadamsaExecutionFailedException When Radamsa terminated with non-zero status code
     * @throws IOException                     When the invocation of Radamsa failed
     */
    public byte[] fuzz(final RadamsaParameters parameters) throws IOException {
        if (parameters == null) {
            throw new IllegalArgumentException("No parameters provided");
        } else if (parameters.getSample().isEmpty() && parameters.getSamplePaths().isEmpty()) {
            throw new IllegalArgumentException("No sample data provided");
        }

        final var radamsaCommand = new ArrayList<String>();
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

    /**
     * @return The version of Radamsa
     * @throws IOException                     When the invocation of Radamsa failed
     * @throws RadamsaExecutionFailedException When Radamsa terminated with non-zero status code
     */
    public String getVersion() throws IOException {
        final List<String> command = List.of(radamsaPath, "-V");
        final ExecutionResult executionResult = commandExecutor.execute(command);

        if (executionResult.getExitCode() != 0) {
            throw new RadamsaExecutionFailedException(command, executionResult);
        }

        return executionResult.getStdoutOutput()
                .map(String::trim)
                .map(output -> output.split(" ", 2))
                .filter(outputParts -> outputParts.length == 2)
                .map(outputParts -> outputParts[1])
                .orElseThrow(() -> new IOException("Missing or unexpected output for command " + command));
    }

}
