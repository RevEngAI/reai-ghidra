package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import ghidra.program.model.listing.Function;

import java.util.Optional;


public record GhidraFunctionMatchWithSignature(
        Function function,
        FunctionMatch functionMatch,
        Optional<FunctionDataTypeMessage> signature
) {

    public GhidraFunctionMatchWithSignature(GhidraFunctionMatch functionMatch, FunctionDataTypeMessage signature) {
        this(functionMatch.function(), functionMatch.functionMatch(), Optional.ofNullable(signature));
    }

    public static GhidraFunctionMatchWithSignature createWith(GhidraFunctionMatch functionMatch, GhidraRevengService apiService) {
        var signature = apiService.getFunctionSignatureArtifact(functionMatch.functionMatch().nearest_neighbor_binary_id(), functionMatch.functionMatch().nearest_neighbor_id());
        return new GhidraFunctionMatchWithSignature(functionMatch.function(), functionMatch.functionMatch(), signature);
    }

}
