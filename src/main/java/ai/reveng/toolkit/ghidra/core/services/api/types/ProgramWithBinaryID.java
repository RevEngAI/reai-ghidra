package ai.reveng.toolkit.ghidra.core.services.api.types;

import ghidra.program.model.listing.Program;

public record ProgramWithBinaryID(
        Program program,
        BinaryID binaryID
) {
}
