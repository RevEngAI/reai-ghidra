package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import org.json.JSONObject;

/**
 * Based on the Typedef artifact from BinSync.
 */
public record Typedef(
        String last_change,
        String name,
        String type
) {

        public static Typedef fromJsonObject(JSONObject obj) {
            return new Typedef(
                    !obj.isNull("last_change") ? obj.getString("last_change") : null,
                    obj.getString("name"),
                    obj.getString("type")
            );
        }


        public static boolean matches(JSONObject obj) {
            return obj.has("type") && obj.has("name");
        }
}
