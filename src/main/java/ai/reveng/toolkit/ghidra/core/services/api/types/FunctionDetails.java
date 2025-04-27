package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

/**
 * Record representing detailed function information from the RevEng.AI API
 */
public record FunctionDetails(
        FunctionID functionId,
        String functionName,
        Long functionVaddr,
        Long functionSize,
        AnalysisID analysisId,
        BinaryID binaryId,
        String binaryName,
        BinaryHash sha256Hash

) {
    public static FunctionDetails fromJSON(JSONObject json) {
        return new FunctionDetails(
                new FunctionID(json.getInt("function_id")),
                json.getString("function_name"),
                json.getLong("function_vaddr"),
                json.getLong("function_size"),
                new AnalysisID(json.getInt("analysis_id")),
                new BinaryID(json.getInt("binary_id")),
                json.getString("binary_name"),
                new BinaryHash(json.getString("sha_256_hash"))
        );
    }
}
