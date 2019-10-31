package com.github.nscuro.bradamsang.radamsa;

import lombok.Builder;
import lombok.Data;

import java.nio.file.Path;
import java.util.Optional;

@Data
@Builder(builderClassName = "Builder")
public final class RadamsaParameters {

    private final Integer count;

    private final Long seed;

    private final byte[] sample;

    private final Path outputDirectoryPath;

    Optional<Integer> getCount() {
        return Optional.ofNullable(count);
    }

    Optional<Long> getSeed() {
        return Optional.ofNullable(seed);
    }

}
