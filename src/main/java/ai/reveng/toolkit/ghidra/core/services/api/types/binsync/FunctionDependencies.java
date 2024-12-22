package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import org.json.JSONArray;

import java.util.ArrayList;

/**
 *    Describes the dependencies of a function.
 *    Has no corresponding artifact in BinSync, in the RevEng.AI response it's just a list of
 *    type artifacts
 *
 *    For ease of use we split it into its own record, and split the type of artifacts into their own
 *    arrays. This needs to happen for deserialization anyway
 */
public record FunctionDependencies(
        Typedef[] typedefs,
        Struct[] structs
) {
    public static FunctionDependencies fromJsonObject(JSONArray funcDeps) {
        // We need to distinguish the object type somehow
        if (funcDeps.isEmpty()) {
            return null;
        }
        var typedefs = new ArrayList<Typedef>();
        var structs = new ArrayList<Struct>();

        // For each element in the array check if it's a Typedef or a Struct
        for (int i = 0; i < funcDeps.length(); i++) {
            // If it's a Typedef
            if (Typedef.matches(funcDeps.getJSONObject(i))) {
                typedefs.add(Typedef.fromJsonObject(funcDeps.getJSONObject(i)));
            }
            // If it's a Struct
            if (Struct.matches(funcDeps.getJSONObject(i))) {
                structs.add(Struct.fromJsonObject(funcDeps.getJSONObject(i)));
            }
        }

        return new FunctionDependencies(
                typedefs.toArray(new Typedef[0]),
                structs.toArray(new Struct[0])
        );
    }
}
