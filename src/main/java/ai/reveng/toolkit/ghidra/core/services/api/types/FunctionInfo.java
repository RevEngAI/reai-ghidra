package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

public record FunctionInfo(
        FunctionID functionID,
        String functionName,
        String functionMangledName,
        // This is an absolute address
        Long functionVirtualAddress,
        Integer functionSize
) {
    public static FunctionInfo fromJSONObject(JSONObject json) {
        return new FunctionInfo(
                new FunctionID(json.getInt("function_id")),
                json.getString("function_name"),
                json.getString("function_mangled_name"),
                json.getLong("function_vaddr"),
                json.getInt("function_size")
        );
    }
}
