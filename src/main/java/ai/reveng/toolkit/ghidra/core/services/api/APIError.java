package ai.reveng.toolkit.ghidra.core.services.api;

import org.json.JSONObject;

public record APIError(
        String code,
        String message
) {
    public static APIError fromJSONObject(JSONObject json) {
        return new APIError(
                json.getString("code"),
                json.getString("message")
        );
    }
}
