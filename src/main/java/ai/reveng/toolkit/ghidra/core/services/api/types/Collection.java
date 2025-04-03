package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import org.json.JSONObject;

import java.util.List;

public record Collection(
        int collectionID,
        String collectionScope,
        String collectionName,
        String owner,
        String creationDate,
        String modelName,
        String description,
        List<String> tags
) {
    public static Collection fromJSONObject(JSONObject json){
        return new Collection(
                json.getInt("collection_id"),
                json.getString("collection_scope"),
                json.getString("collection_name"),
                json.getString("collection_owner"),
                json.getString("creation"),
                json.getString("model_name"),
                json.getString("description"),
                json.getJSONArray("collection_tags").toList().stream().map(Object::toString).toList()
        );
    }

    public static Collection fromSmallJSONObject(JSONObject json, ModelName modelName){
        return new Collection(
                -1,
                json.getString("scope"),
                json.getString("name"),
                "",
                "",
                modelName.modelName(),
                "",
                List.of()
        );
    }
}
