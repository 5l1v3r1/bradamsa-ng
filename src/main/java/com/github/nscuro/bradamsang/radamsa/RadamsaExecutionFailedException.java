package com.github.nscuro.bradamsang.radamsa;

import com.github.nscuro.bradamsang.io.ExecutionResult;

import java.util.List;

import static java.lang.String.format;

public final class RadamsaExecutionFailedException extends RadamsaException {

    RadamsaExecutionFailedException(final List<String> command, final ExecutionResult executionResult) {
        super(format("Radamsa command %s failed: %s", command, executionResult));
    }

}
