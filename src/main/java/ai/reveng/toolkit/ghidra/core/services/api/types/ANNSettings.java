package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

public record ANNSettings(
        Integer resultPerFunction,
        Boolean debugMode,
        Double distance

) {
    public static ANNSettings fromJSONObject(JSONObject json){
        return new ANNSettings(
                json.getInt("result_per_function"),
                json.getBoolean("debug_mode"),
                json.getDouble("distance")
        );
    }
    public JSONObject toJSON(){
        return new JSONObject()
                .put("result_per_function", this.resultPerFunction)
                .put("debug_mode", this.debugMode)
                .put("distance", this.distance);
    }

}
