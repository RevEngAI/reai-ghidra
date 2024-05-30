package ai.reveng.toolkit.ghidra.core.services.api.types;


import org.json.JSONObject;

import java.util.LinkedList;
import java.util.List;

public record ANNResult(
        ANNSettings settings,
        Boolean success,
        List<FunctionMatch> functionMatchesList
) {
    public static ANNResult fromJSONObject(JSONObject json) {
        var matches = new LinkedList<FunctionMatch>();
        json.getJSONArray("function_matches").forEach(
                o -> {
                    if ((o instanceof JSONObject)) {
                        matches.add(FunctionMatch.fromJSONObject((JSONObject) o));
                    }
                    else {
                        throw new RuntimeException("Expected JSONObject");
                    }
                }

        );

        return new ANNResult(
                ANNSettings.fromJSONObject(json.getJSONObject("settings")),
                json.getBoolean("success"),
                matches
        );
    }
}
