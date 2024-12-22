package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import org.json.JSONObject;

/**
 * Based directly on the StructMember artifact from BinSync.
 */
public record StructMember(
        String last_change,
        String name,
        int offset,
        String type,
        int size
) {

    public static StructMember fromJsonObject(JSONObject jsonObject) {
        return new StructMember(
                !jsonObject.isNull("last_change") ? jsonObject.getString("last_change") : null,
                jsonObject.getString("name"),
                jsonObject.getInt("offset"),
                jsonObject.getString("type"),
                jsonObject.getInt("size")
        );
    }
}
