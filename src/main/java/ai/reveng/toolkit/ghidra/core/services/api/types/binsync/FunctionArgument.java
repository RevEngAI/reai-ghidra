package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;


import org.json.JSONObject;

/**
 * {
 *  *         "offset": 0,
 *  *         "size": 8,
 *  *         "last_change": null,
 *  *         "name": "param_1",
 *  *         "type": "char *"
 *  *       },
 */
public record FunctionArgument(
        int offset,
        int size,
        String last_change,
        String name,
        String type
) {

        public static FunctionArgument fromJsonObject(JSONObject arg) {
            return new FunctionArgument(
                    arg.getInt("offset"),
                    arg.getInt("size"),
                    !arg.isNull("last_change") ? arg.getString("last_change") : null,
                    arg.getString("name"),
                    arg.getString("type")
            );
        }
}
