package ai.reveng.toolkit.ghidra.core.services.api.types;

import ghidra.program.model.listing.Function;

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

    public FunctionID nearest_neighbor_id() {
        return functionMatch.nearest_neighbor_id();
    }
    public double similarity() {
        return functionMatch.similarity();
    }

}
