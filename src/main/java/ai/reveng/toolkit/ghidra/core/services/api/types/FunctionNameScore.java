package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

public record FunctionNameScore(
        FunctionID functionID,
        BoxPlot score
) {
    public static FunctionNameScore fromJSONObject(JSONObject jsonObject) {
        var boxplotJson = jsonObject.getJSONObject("box_plot");
        return new FunctionNameScore(
                new FunctionID(jsonObject.getInt("function_id")),
                BoxPlot.fromJSONObject(boxplotJson)
        );
    }
}
