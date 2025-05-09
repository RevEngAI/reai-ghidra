package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.FunctionDataTypeMessage;
import ghidra.program.model.listing.Function;

import java.util.Optional;


/**
 * The signature is not final because it can be computed on demand
 *
 * @param function      The local function that we searched for matches for
 * @param functionMatch A match that was found and returned by the RevEng.AI server
 * @param signature     The optional signature of the function match
 */
public class GhidraFunctionMatchWithSignature {
    private final Function function;
    private final FunctionMatch functionMatch;
    private Optional<FunctionDataTypeMessage> signature;
    private final Optional<BoxPlot> nameScore;

    public GhidraFunctionMatchWithSignature(
            Function function,
            FunctionMatch functionMatch,
            Optional<FunctionDataTypeMessage> signature,
            Optional<BoxPlot> nameScore) {
        if (function == null) {
            throw new IllegalArgumentException("Function cannot be null");
        }
        if (functionMatch == null) {
            throw new IllegalArgumentException("FunctionMatch cannot be null");
        }
        if (nameScore == null) {
            throw new IllegalArgumentException("NameScore cannot be null, use Optional.empty() instead");
        }
        this.function = function;
        this.functionMatch = functionMatch;
        this.signature = signature;
        this.nameScore = nameScore;
    }

    public GhidraFunctionMatchWithSignature(GhidraFunctionMatch functionMatch, FunctionDataTypeMessage signature, BoxPlot nameScore) {
        this(functionMatch.function(), functionMatch.functionMatch(), Optional.ofNullable(signature), Optional.ofNullable(nameScore));
    }

    public Function function() {
        return function;
    }

    public FunctionMatch functionMatch() {
        return functionMatch;
    }

    public Optional<FunctionDataTypeMessage> signature() {
        return signature;
    }

    public void setSignature(Optional<FunctionDataTypeMessage> signature) {
        this.signature = signature;
    }

    public Optional<BoxPlot> nameScore() {
        return nameScore;
    }
}