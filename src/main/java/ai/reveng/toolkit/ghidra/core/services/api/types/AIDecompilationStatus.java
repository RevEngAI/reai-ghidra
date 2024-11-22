package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

public record AIDecompilationStatus(
        String status, // TODO: Change to enum
        String decompilation,
        JSONObject functionMapping // TODO: Figure out what this is, and why it's relevant
) {
    public static AIDecompilationStatus fromJSONObject(JSONObject data) {
        return new AIDecompilationStatus(
                data.getString("status"),
                !data.isNull("decompilation") ? data.getString("decompilation") : null,
                data.getJSONObject("function_mapping")
        );
    }
}
