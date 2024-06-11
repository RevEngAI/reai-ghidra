package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

public record FunctionBoundary(
        String function_name,
        long start,
        long end
) {

    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        obj.put("name", function_name);
        obj.put("start_addr", start);
        obj.put("end_addr", end);
        return obj;
    }
}
