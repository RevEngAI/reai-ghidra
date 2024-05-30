package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.List;

import ai.reveng.toolkit.ghidra.core.services.api.types.*;


/**
 * Service for interacting with the RevEngAi API
 * This is a generic Java Interface and should not use any Ghidra specific classes
 */
public interface TypedApiInterface {
    public Object echo();

    // Analysis

    List<AnalysisResult> search(
            BinaryHash hash,
            String binaryName,
            Collection collection,
            AnalysisStatus state);

    BinaryID analyse(BinaryHash binHash,
                     Long baseAddress,
                     List<FunctionBoundary> functionBounds, ModelName modelName);

    BinaryID analyse(AnalysisOptionsBuilder binHash);



    default ApiResponse delete(BinaryID binID) {
        throw new UnsupportedOperationException("delete not implemented yet");
    }


    List<FunctionInfo> getFunctionInfo(BinaryID binaryID);

    default List<AnalysisResult> recentAnalyses() {
        throw new UnsupportedOperationException("recentAnalyses not implemented yet");
    }


    default AnalysisStatus status(BinaryID binID){
        throw new UnsupportedOperationException("status not implemented yet");
    };


    // Utility

    default Object getConfigurationSettings(){
        throw new UnsupportedOperationException("getConfigurationSettings not implemented yet");
    }

    /**
     * https://docs.reveng.ai/#/Utility/get_search
     */
    default List<AnalysisResult> search(BinaryHash hash) {
        throw new UnsupportedOperationException("search not implemented yet");
    }


    BinaryHash upload(Path binPath) throws FileNotFoundException;

    default Object getAvailableModels(){
        throw new UnsupportedOperationException("getAvailableModels not implemented yet");
    }


    // Analysis Info



    // Collections


    // ANN
    List<FunctionMatch> annSymbolsForFunctions(List<FunctionID> fID,
                                               int resultsPerFunction,
                                               double distance);

    List<FunctionMatch> annSymbolsForBinary(BinaryID binID, int resultsPerFunction, double distance);


//    public default Object explain(String decompiledFunction){
//        throw new UnsupportedOperationException("explain not implemented yet");
//    };

    // Health
    boolean healthStatus();

    String healthMessage();

    List<Collection> collectionQuickSearch(ModelName modelName);

    List<ModelInfo> models();
}

