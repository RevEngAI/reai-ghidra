package ai.reveng.toolkit.ghidra.core.services.api.types;

import ghidra.program.model.listing.Function;

import java.util.Objects;

/**
 * Extension of a {@link FunctionMatch}
 * it contains the original FunctionMatch, but combines it with information relating to the original Ghidra Function
 *
 */
public record GhidraFunctionMatch(
        Function function,
        String nearest_neighbor_function_name,
        String nearest_neighbor_binary_name,
        double confidence,
        FunctionMatch functionMatch
) {
//    public GhidraFunctionMatch {
//        Objects.requireNonNull(function);
//    }
    public GhidraFunctionMatch(Function function, FunctionMatch functionMatch) {
        this(
                function,
                functionMatch.nearest_neighbor_function_name(),
                functionMatch.nearest_neighbor_binary_name(),
                functionMatch.confidence(),
                functionMatch
        );
    }
}
