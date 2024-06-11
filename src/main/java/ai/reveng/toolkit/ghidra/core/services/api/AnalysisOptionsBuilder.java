package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryHash;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionBoundary;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.function.Function;

public class AnalysisOptionsBuilder {
    private JSONObject options;

    public AnalysisOptionsBuilder() {
        options = new JSONObject();
        options.put("size_in_bytes", 0);
    }

    public AnalysisOptionsBuilder modelName(ModelName modelName) {
        options.put("model_name", modelName.modelName());
        return this;
    }

    public AnalysisOptionsBuilder functionBoundaries(long base, List<FunctionBoundary> functionList){
        JSONObject symbols = new JSONObject();
        symbols.put("base_addr", base);

        JSONArray functions = new JSONArray();
        functionList.forEach(f -> functions.put(f.toJSON()));

        symbols.put("functions", functions);
        options.put("symbols", symbols);
        return this;
    }

    public AnalysisOptionsBuilder hash(BinaryHash hash) {
        options.put("sha_256_hash", hash.sha256());
        return this;
    }

    public JSONObject toJSON() {
        if (!options.has("size_in_bytes")){
            throw new IllegalArgumentException("size_in_bytes is required");
        }
        if (!options.has("model_name")){
            throw new IllegalArgumentException("model_name is required");
        }

        return options;
    }


    public AnalysisOptionsBuilder fileName(String name) {
        options.put("file_name", name);
        return this;
    }

    public AnalysisOptionsBuilder size(long size) {
        options.put("size_in_bytes", size);
        return this;
    }
}
