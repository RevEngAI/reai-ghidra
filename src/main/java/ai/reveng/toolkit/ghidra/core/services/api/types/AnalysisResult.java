package ai.reveng.toolkit.ghidra.core.services.api.types;


import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import org.json.JSONObject;

/*
 */
public record AnalysisResult(
        AnalysisID analysisID,
        String binary_name,
        String creation,
        Integer model_id,
        String model_name,
        BinaryHash sha_256_hash,
        AnalysisStatus status
//        AnalysisScope analysis_scope,
) {
    public static AnalysisResult fromJSONObject(TypedApiInterface api, JSONObject json) {
//        throw new UnsupportedOperationException("fromJSONObject not implemented yet");
        var analysisId = new AnalysisID(json.getInt("analysis_id"));
        var analysisStatus = api.status(analysisId);
        return new AnalysisResult(
                analysisId,
                json.getString("binary_name"),
                json.getString("creation"),
                json.has("model_id") ? json.getInt("model_id") : null,
                json.getString("model_name"),
                new BinaryHash(json.getString("sha_256_hash")),
                analysisStatus
        );
    }
}
