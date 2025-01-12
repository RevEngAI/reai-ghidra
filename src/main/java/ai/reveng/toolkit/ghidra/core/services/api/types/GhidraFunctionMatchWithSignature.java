package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import ghidra.program.model.listing.Function;

import java.util.Optional;


public record GhidraFunctionMatchWithSignature(
        Function function,
        FunctionMatch functionMatch,
        Optional<FunctionDataTypeMessage> signature
) {
}
