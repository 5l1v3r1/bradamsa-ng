package com.github.nscuro.bradamsang.radamsa;

import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public final class RadamsaParameters {

    private final byte[] sample;

    private final List<Path> samplePaths;

    public RadamsaParameters(final byte[] sample, final List<Path> samplePaths) {
        this.sample = sample;
        this.samplePaths = samplePaths;
    }

    public Optional<byte[]> getSample() {
        return Optional.ofNullable(sample);
    }

    public List<Path> getSamplePaths() {
        return Optional.ofNullable(samplePaths)
                .orElseGet(Collections::emptyList);
    }

}
