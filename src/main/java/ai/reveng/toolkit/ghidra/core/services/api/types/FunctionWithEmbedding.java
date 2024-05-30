package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

public record FunctionWithEmbedding(
        String name,
        Integer size,
        String model,
        FunctionEmbeddingVector embedding,
        Integer vaddr

) {
    public static FunctionWithEmbedding fromJsonObject(JSONObject json){
        if (!json.getString("type").equals("function")){
            throw new RuntimeException("Not a function object!");
        }
        return new FunctionWithEmbedding(
                json.getString("name"),
                json.getInt("size"),
                json.getString("model"),
                FunctionEmbeddingVector.fromJsonObject(json.getJSONArray("embedding")),
                json.getInt("vaddr")
        );
    }
}
