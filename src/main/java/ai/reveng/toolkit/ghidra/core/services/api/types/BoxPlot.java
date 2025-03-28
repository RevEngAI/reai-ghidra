package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

/**
 * The BoxPlot object returned by https://api.reveng.ai/v2/docs#tag/Confidence-Scores/operation/function_name_score_v2_confidence_functions_name_score_post
 */
public record BoxPlot(
        double min,
        double max,
        double average,
        double upper_quartile,
        double lower_quartile,
        int positive_count,
        int negative_count
) {
    public static BoxPlot fromJSONObject(JSONObject boxplotJson) {
        return new BoxPlot(
                boxplotJson.getDouble("min"),
                boxplotJson.getDouble("max"),
                boxplotJson.getDouble("average"),
                boxplotJson.getDouble("upper_quartile"),
                boxplotJson.getDouble("lower_quartile"),
                boxplotJson.getInt("positive_count"),
                boxplotJson.getInt("negative_count")
        );
    }
}
