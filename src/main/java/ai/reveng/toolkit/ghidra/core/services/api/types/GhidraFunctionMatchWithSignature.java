package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import ghidra.program.model.listing.Function;

import java.util.Optional;

/**
 *
 * @param function The local function that we searched for matches for
 * @param functionMatch A match that was found and returned by the RevEng.AI server
 * @param signature The optional signature of the function match
 */
public record GhidraFunctionMatchWithSignature(
        Function function,
        FunctionMatch functionMatch,
        Optional<FunctionDataTypeMessage> signature,
        Optional<BoxPlot> nameScore
) {
    public GhidraFunctionMatchWithSignature {
        if (function == null) {
            throw new IllegalArgumentException("Function cannot be null");
        }
        if (functionMatch == null) {
            throw new IllegalArgumentException("FunctionMatch cannot be null");
        }

        if (nameScore == null) {
            throw new IllegalArgumentException("NameScore cannot be null, use Optional.empty() instead");
        }
    }

    public GhidraFunctionMatchWithSignature(GhidraFunctionMatch functionMatch, FunctionDataTypeMessage signature, BoxPlot nameScore) {
        this(functionMatch.function(), functionMatch.functionMatch(), Optional.ofNullable(signature), Optional.ofNullable(nameScore));
    }

    public static GhidraFunctionMatchWithSignature createWith(GhidraFunctionMatch functionMatch, GhidraRevengService apiService) {
        var signature = apiService.getFunctionSignatureArtifact(functionMatch.functionMatch().nearest_neighbor_binary_id(), functionMatch.functionMatch().nearest_neighbor_id());
        BoxPlot nameScore = apiService.getNameScoreForMatch(functionMatch);
        return new GhidraFunctionMatchWithSignature(functionMatch, signature.orElse(null), nameScore);
    }

}
