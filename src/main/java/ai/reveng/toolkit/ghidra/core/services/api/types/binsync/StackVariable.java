package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 *
 {
 "offset": -152,
 "size": 144,
 "last_change": null,
 "name": "local_98",
 "type": "stat64",
 "addr": 8138
 }
 */
public record StackVariable(
        String last_change, int offset,
        String name, String type, int size,
        int addr
) {

    public static StackVariable fromJsonObject(JSONObject stackVar) {
        return new StackVariable(
                !stackVar.isNull("last_change") ? stackVar.getString("last_change") : null, stackVar.getInt("offset"),
                stackVar.getString("name"), stackVar.getString("type"), stackVar.getInt("size"),
                stackVar.getInt("addr")
        );
    }

    public static StackVariable[] fromJsonArray(JSONArray stackVars) {
        StackVariable[] stackVariables = new StackVariable[stackVars.length()];
        for (int i = 0; i < stackVars.length(); i++) {
            stackVariables[i] = fromJsonObject(stackVars.getJSONObject(i));
        }
        return stackVariables;
    }
}
