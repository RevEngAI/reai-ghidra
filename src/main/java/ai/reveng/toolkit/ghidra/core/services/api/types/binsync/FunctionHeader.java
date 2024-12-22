package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * "header": {
 *     "args": {
 *       "0x0": {
 *         "offset": 0,
 *         "size": 8,
 *         "last_change": null,
 *         "name": "param_1",
 *         "type": "char *"
 *       },
 *       "0x1": {
 *         "offset": 1,
 *         "size": 8,
 *         "last_change": null,
 *         "name": "param_2",
 *         "type": "char *"
 *       }
 *     },
 *     "last_change": null,
 *     "name": "FUN_00101fca",
 *     "addr": 8138,
 *     "type": "uint"
 *   },
 */
public record FunctionHeader(
        String last_change,
        String name,
        long addr,
        String type,
        FunctionArgument[] args

) {
    public static FunctionHeader fromJsonObject(JSONObject header) {
        // Create function argument array

        List<FunctionArgument> args = new ArrayList<>();
        JSONObject argsJson = header.getJSONObject("args");
        for (String key : argsJson.keySet()) {
            args.add(FunctionArgument.fromJsonObject(argsJson.getJSONObject(key)));
        }

        return new FunctionHeader(
                !header.isNull("last_change") ? header.getString("last_change") : null,
                header.getString("name"),
                header.getLong("addr"),
                header.getString("type"),
                args.toArray(new FunctionArgument[0])
        );
    }
}
