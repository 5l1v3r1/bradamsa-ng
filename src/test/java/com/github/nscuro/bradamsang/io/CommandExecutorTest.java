package com.github.nscuro.bradamsang.io;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class CommandExecutorTest {

    private CommandExecutor commandExecutor;

    @BeforeEach
    void beforeEach() {
        commandExecutor = new CommandExecutor();
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void placeholderTest() throws IOException {
        final ExecutionResult executionResult = commandExecutor.execute(Arrays.asList("grep", "test"),
                "estt\ntest\nttse\n".getBytes(StandardCharsets.UTF_8));
        assertThat(executionResult.getExitCode()).isZero();
        assertThat(executionResult.getStdoutOutput()).contains("test\n");
        assertThat(executionResult.getStderrOutput()).contains("");
    }

}