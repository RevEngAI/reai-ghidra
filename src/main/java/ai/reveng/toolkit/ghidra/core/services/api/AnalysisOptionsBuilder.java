package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisScope;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryHash;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionBoundary;
import ghidra.program.model.listing.Program;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.function.Function;

public class AnalysisOptionsBuilder {
    private JSONObject options;
    private Program program;

    private AnalysisOptionsBuilder() {
        options = new JSONObject();
        options.put("size_in_bytes", 0);
        options.put("tags", new JSONArray());
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
    public AnalysisOptionsBuilder advancedAnalysis(boolean advanced) {
        options.put("advanced_analysis", advanced);
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

    public AnalysisOptionsBuilder scope(AnalysisScope scope){
        options.put("binary_scope", scope.scope);
        return this;
    }

    public static AnalysisOptionsBuilder forProgram(Program program) {
        return new AnalysisOptionsBuilder()
                .hash(new BinaryHash(program.getExecutableSHA256()))
                .fileName(program.getName())
                .functionBoundaries(
                        program.getImageBase().getOffset(),
                        GhidraRevengService.exportFunctionBoundaries(program
                        )
                );
    }

    public AnalysisOptionsBuilder skipSBOM(boolean b) {
        options.put("skip_sbom", b);
        return this;
    }
    public AnalysisOptionsBuilder skipScraping(boolean b) {
        options.put("skip_scraping", b);
        return this;
    }

    public AnalysisOptionsBuilder skipCVE(boolean b) {
        options.put("skip_cves", b);
        return this;
    }
    public AnalysisOptionsBuilder dynamicExecution(boolean b) {
        options.put("dynamic_execution", b);
        return this;
    }

    public AnalysisOptionsBuilder skipCapabilities(boolean b) {
        options.put("skip_capabilities", b);
        return this;
    }
    public AnalysisOptionsBuilder addTag(String tag) {
        options.getJSONArray("tags").put(tag);
        return this;
    }

    public AnalysisOptionsBuilder addTags(List<String> tags) {
        JSONArray tagArray = options.getJSONArray("tags");
        tags.forEach(tagArray::put);
        return this;
    }

    public AnalysisOptionsBuilder architecture(String arch) {
        options.put("isa_options", arch);
        return this;
    }
}
