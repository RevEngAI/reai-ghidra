package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;

import javax.annotation.Nullable;


/**
 * Service for interacting with the RevEngAi API
 * This is a generic Java Interface and should not use any Ghidra specific classes
 *
 * It aims to stick close to the API functions themselves.
 * E.g. if a feature is implemented via two API calls, it should be implemented as two methods here.
 *
 * Wrapping this feature into one conceptual method should then happen inside the {@link ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService}
 *
 *
 */
public interface TypedApiInterface {
    // Analysis
    List<AnalysisResult> search(
            BinaryHash hash,
            String binaryName,
            Collection collection,
            AnalysisStatus state);

    BinaryID analyse(AnalysisOptionsBuilder binHash);



    default Object delete(BinaryID binID) {
        throw new UnsupportedOperationException("delete not implemented yet");
    }


    default List<FunctionInfo> getFunctionInfo(BinaryID binaryID) {
        throw new UnsupportedOperationException("getFunctionInfo not implemented yet");
    }

    default List<AnalysisResult> recentAnalyses() {
        throw new UnsupportedOperationException("recentAnalyses not implemented yet");
    }


    default AnalysisStatus status(BinaryID binID){
        throw new UnsupportedOperationException("status not implemented yet");
    };

    /**
     * https://docs.reveng.ai/#/Utility/get_search
     */
    default List<AnalysisResult> search(BinaryHash hash) {
        throw new UnsupportedOperationException("search not implemented yet");
    }


    default BinaryHash upload(Path binPath) throws FileNotFoundException {
        throw new UnsupportedOperationException("upload not implemented yet");
    }

    // ANN
    default List<FunctionMatch> annSymbolsForFunctions(List<FunctionID> fID,
                                                       int resultsPerFunction,
                                                       double distance, boolean debug) {
        throw new UnsupportedOperationException("annSymbolsForFunctions not implemented yet");
    }

    default List<FunctionMatch> annSymbolsForBinary(BinaryID binID, int resultsPerFunction, double distance, boolean debugMode){
        return this.annSymbolsForBinary(binID, resultsPerFunction, distance, debugMode, null);
    }

    default List<FunctionMatch> annSymbolsForBinary(
            BinaryID binID,
            int resultsPerFunction,
            double distance,
            boolean debugMode,
            List<Collection> collections
    ) {
        throw new UnsupportedOperationException("annSymbolsForBinary not implemented yet");
    }


//    public default Object explain(String decompiledFunction){
//        throw new UnsupportedOperationException("explain not implemented yet");
//    };

    // Health
    default boolean healthStatus() {
        throw new UnsupportedOperationException("healthStatus not implemented yet");
    }

    default String healthMessage() {
        throw new UnsupportedOperationException("healthMessage not implemented yet");
    }

    List<Collection> collectionQuickSearch(ModelName modelName);

    List<ModelName> models();

    List<Collection> collectionQuickSearch(String searchTerm);

    default List<Collection> searchCollections(String searchTerm,
                                       @Nullable List<SearchFilter> filter,
                                       int limit,
                                       int offset,
                                       @Nullable CollectionResultOrder orderBy,
                                       @Nullable OrderDirection order
    ) {
        throw new UnsupportedOperationException("searchCollections not implemented yet");
    }

    String getAnalysisLogs(BinaryID binID);

    String getAnalysisLogs(AnalysisID analysisID);

    void authenticate() throws InvalidAPIInfoException;

    default Object generateFunctionDataTypes(AnalysisID analysisID, List<FunctionID> functionIDS) {
        throw new UnsupportedOperationException("generateFunctionDataTypes not implemented yet");
    }

    default Optional<FunctionDataTypeStatus> getFunctionDataTypes(AnalysisID analysisID, FunctionID functionID) {
        throw new UnsupportedOperationException("getFunctionDataTypes not implemented yet");
    }


    default AnalysisID getAnalysisIDfromBinaryID(BinaryID binaryID) {
        throw new UnsupportedOperationException("getAnalysisIDfromBinaryID not implemented yet");
    }

    default boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
        throw new UnsupportedOperationException("triggerAIDecompilationForFunctionID not implemented yet");
    }

    default AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {
        throw new UnsupportedOperationException("pollAIDecompileStatus not implemented yet");
    }

    void renameFunctions(Map<FunctionID, String> renameDict);

    default FunctionNameScore getNameScore(FunctionMatch match) {
        throw new UnsupportedOperationException("getNameScore not implemented yet");
    }

}

