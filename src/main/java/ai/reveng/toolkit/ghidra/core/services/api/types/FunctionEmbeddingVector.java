package ai.reveng.toolkit.ghidra.core.services.api.types;

import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;

public record FunctionEmbeddingVector(
        List<Double> embedding
) {
    public static FunctionEmbeddingVector fromJsonObject(JSONArray json){
        if (json.length() != 256){
            throw new RuntimeException("Embedding of unexpected length!");
        }
        List<Double> embedding = new ArrayList<>();
        for (int i = 0; i < json.length(); i++) {
            embedding.add(json.getDouble(i));
        }
        return new FunctionEmbeddingVector(embedding);
    }

}
