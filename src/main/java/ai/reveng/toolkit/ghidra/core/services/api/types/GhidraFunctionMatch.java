package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import ghidra.program.model.listing.Function;

import java.util.Objects;
import java.util.Optional;

/**
 * Extension of a {@link FunctionMatch}
 * it contains the original FunctionMatch, but combines it with information relating to the original Ghidra Function
 *
 */
public record GhidraFunctionMatch(
        Function function,
        FunctionMatch functionMatch
) {

    public String nearest_neighbor_function_name() {
        return functionMatch.nearest_neighbor_function_name();
    }

    public String nearest_neighbor_binary_name() {
        return functionMatch.nearest_neighbor_binary_name();
    }

    public double confidence() {
        return functionMatch.confidence();
    }

}
