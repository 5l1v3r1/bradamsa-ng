package com.github.nscuro.bradamsang.io;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class WslCommandExecutorTest {

    private static final String DISTRO_NAME = "distroName";

    @Mock
    private NativeCommandExecutor nativeCommandExecutorMock;

    private WslCommandExecutor wslCommandExecutor;

    @BeforeEach
    void beforeEach() {
        wslCommandExecutor = new WslCommandExecutor(nativeCommandExecutorMock, DISTRO_NAME);
    }

    @Nested
    class ConstructorTest {

        @Test
        void shouldThrowExceptionWhenNativeCommandExecutorIsNull() {
            assertThatNullPointerException()
                    .isThrownBy(() -> new WslCommandExecutor(null, DISTRO_NAME));
        }

        @Test
        void shouldThrowExceptionWhenDistroNameIsNullOrBlank() {
            assertThatNullPointerException()
                    .isThrownBy(() -> new WslCommandExecutor(nativeCommandExecutorMock, null));

            assertThatNullPointerException()
                    .isThrownBy(() -> new WslCommandExecutor(nativeCommandExecutorMock, ""));

            assertThatNullPointerException()
                    .isThrownBy(() -> new WslCommandExecutor(nativeCommandExecutorMock, " "));
        }

    }

    @Nested
    class ExecuteTest {

        @Test
        void shouldPrependCommandWithWslCommand() throws IOException {
            final List<String> command = Arrays.asList("echo", "666");

            final ExecutionResult executionResultMock = mock(ExecutionResult.class);

            given(nativeCommandExecutorMock.execute(anyList(), any()))
                    .willReturn(executionResultMock);

            assertThat(wslCommandExecutor.execute(command, null))
                    .isEqualTo(executionResultMock);

            //noinspection rawtypes
            final ArgumentCaptor<List> commandCaptor = ArgumentCaptor.forClass(List.class);

            //noinspection unchecked
            verify(nativeCommandExecutorMock).execute(commandCaptor.capture(), eq(null));

            //noinspection unchecked
            final List<String> actualCommand = commandCaptor.getValue();
            assertThat(actualCommand)
                    .isEqualTo(Arrays.asList("wsl", "-d", DISTRO_NAME, "-e", "echo", "666"));
        }

    }

}