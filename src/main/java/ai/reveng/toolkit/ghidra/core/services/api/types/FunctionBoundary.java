package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

public record FunctionBoundary(
        String function_name_mangled,
        long start,
        long end
) {

    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        obj.put("mangled_name", function_name_mangled);
        obj.put("start_addr", start);
        obj.put("end_addr", end);
        return obj;
    }

    public static FunctionBoundary fromJSON(JSONObject json) {
        return new FunctionBoundary(
                json.getString("mangled_name"),
                json.getLong("start_addr"),
                json.getLong("end_addr")
        );
    }
}
