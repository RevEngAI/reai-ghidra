package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import org.json.JSONObject;

import java.util.List;

public record Collection(
        int collectionID,
        String collectionScope,
        String collectionName,
        String lastUpdated,
        String modelName,
        List<String> tags
) {
    public static Collection fromJSONObject(JSONObject json){
        return new Collection(
                json.getInt("collection_id"),
                json.getString("collection_scope"),
                json.getString("collection_name"),
                json.getString("last_updated"),
                json.getString("model_name"),
                json.getJSONArray("tags").toList().stream().map(Object::toString).toList()
        );
    }

    public static Collection fromSmallJSONObject(JSONObject json, ModelName modelName){
        return new Collection(
                -1,
                json.getString("collection_scope"),
                json.getString("collection_name"),
                "",
                modelName.modelName(),
                List.of()
        );
    }
}
