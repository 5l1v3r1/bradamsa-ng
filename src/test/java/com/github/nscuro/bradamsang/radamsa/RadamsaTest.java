package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.command.CommandExecutor;
import com.github.nscuro.bradamsang.command.ExecutionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class RadamsaTest {

    private static final String RADAMSA_PATH = "radamsaPath";

    @Mock
    private CommandExecutor commandExecutorMock;

    private Radamsa radamsa;

    @BeforeEach
    void beforeEach() {
        radamsa = new Radamsa(commandExecutorMock, RADAMSA_PATH);
    }

    @Nested
    class ConstructorTest {

        @Test
        void shouldThrowExceptionWhenCommandExecutorIsNull() {
            assertThatNullPointerException()
                    .isThrownBy(() -> new Radamsa(null, RADAMSA_PATH));
        }

        @Test
        void shouldThrowExceptionWhenRadamsaPathIsNullOrBlank() {
            assertThatNullPointerException()
                    .isThrownBy(() -> new Radamsa(commandExecutorMock, null));

            assertThatNullPointerException()
                    .isThrownBy(() -> new Radamsa(commandExecutorMock, ""));

            assertThatNullPointerException()
                    .isThrownBy(() -> new Radamsa(commandExecutorMock, " "));
        }

    }

    @Nested
    class FuzzTest {

        @Test
        @SuppressWarnings("ConstantConditions")
        void shouldThrowExceptionWhenParametersIsNull() {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> radamsa.fuzz(null));
        }

        @Test
        void shouldTHrowExceptionWhenNeitherSampleNorSamplePathsAreProvided() {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> radamsa.fuzz(new RadamsaParameters(null, null)));
        }

    }

    @Nested
    class GetVersionTest {

        @Test
        void shouldReturnVersion() throws IOException {
            final ExecutionResult executionResultMock = mock(ExecutionResult.class);
            given(executionResultMock.getExitCode())
                    .willReturn(0);
            given(executionResultMock.getStdoutOutput())
                    .willReturn(Optional.of("Radamsa 0.6"));

            given(commandExecutorMock.execute(anyList()))
                    .willReturn(executionResultMock);

            assertThat(radamsa.getVersion())
                    .isEqualTo("0.6");
        }

        @Test
        void shouldThrowExceptionOnUnexpectedOutput() throws IOException {
            final ExecutionResult executionResultMock = mock(ExecutionResult.class);
            given(executionResultMock.getExitCode())
                    .willReturn(0);
            given(executionResultMock.getStdoutOutput())
                    .willReturn(Optional.of("Radamsamsamsamsamsamsa"));

            given(commandExecutorMock.execute(anyList()))
                    .willReturn(executionResultMock);

            assertThatExceptionOfType(IOException.class)
                    .isThrownBy(() -> radamsa.getVersion());
        }

        @Test
        void shouldThrowExceptionWhenCommandReturnsNonZeroExitCode() throws IOException {
            final ExecutionResult executionResultMock = mock(ExecutionResult.class);
            given(executionResultMock.getExitCode())
                    .willReturn(1);

            given(commandExecutorMock.execute(anyList()))
                    .willReturn(executionResultMock);

            assertThatExceptionOfType(RadamsaExecutionFailedException.class)
                    .isThrownBy(() -> radamsa.getVersion());
        }

    }

}