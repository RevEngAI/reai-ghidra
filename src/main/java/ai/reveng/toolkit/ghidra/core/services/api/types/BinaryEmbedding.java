package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

import java.util.List;

public record BinaryEmbedding(
        String architecture,
        List<Float> embedding,
        String model,
        String name,
        String type

) {
    public static BinaryEmbedding fromJsonObject(JSONObject json){
        return new BinaryEmbedding(
                json.getString("architecture"),
                json.getJSONArray("embedding").toList().stream().map(o -> Float.parseFloat(o.toString())).toList(),
                json.getString("model"),
                json.getString("name"),
                json.getString("type")
        );
    }
}
