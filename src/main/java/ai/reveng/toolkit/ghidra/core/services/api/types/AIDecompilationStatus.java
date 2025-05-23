package ai.reveng.toolkit.ghidra.core.services.api.types;

import ghidra.program.model.listing.Program;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 *
 * @param status
 * @param decompilation Pure text, suitable for directly displaying
 * @param rawDecompilation decompilation output that still includes all the placeholders
 * @param functionMapping
 * @param functionMappingFull
 */
public record AIDecompilationStatus(
        String status, // TODO: Change to enum
        String decompilation,
        String rawDecompilation,
        String aiSummary,
        String rawAiSummary,
        Map<String, AIDecompFuncReference> functionMapping, // TODO: Figure out what this is, and why it's relevant
        FullFunctionMapping functionMappingFull // Unclear how that is different to the previous one
) {
    public static AIDecompilationStatus fromJSONObject(JSONObject data) {
        Map<String, AIDecompFuncReference> functionMapping = new HashMap<>();
        if (!data.isNull("function_mapping")) {
            JSONObject funcMapping = data.getJSONObject("function_mapping");
            for (String key : funcMapping.keySet()) {
                functionMapping.put(key, AIDecompFuncReference.fromJSONObject(funcMapping.getJSONObject(key)));
            }
        }

        FullFunctionMapping functionMappingFull = null;
        if (!data.isNull("function_mapping_full")) {
            functionMappingFull = FullFunctionMapping.fromJson(data.getJSONObject("function_mapping_full"));
        }


        return new AIDecompilationStatus(
                data.getString("status"),
                !data.isNull("decompilation") ? data.getString("decompilation") : null,
                !data.isNull("raw_decompilation") ? data.getString("raw_decompilation") : null,
                !data.isNull("ai_summary") ? data.getString("ai_summary") : null,
                !data.isNull("raw_ai_summary") ? data.getString("raw_ai_summary") : null,
                functionMapping,
                functionMappingFull
        );
    }

    public String getMarkedUpSummary() {
        return aiSummary;
    }

    record AIDecompFuncReference(String name, Integer addr, boolean isExternal) {
        public static AIDecompFuncReference fromJSONObject(JSONObject data) {
            return new AIDecompFuncReference(
                    data.getString("name"),
                    data.getInt("addr"),
                    data.getBoolean("is_external")
            );
        }
    }

    public record FullFunctionMapping(
            JSONObject inverse_string_map,
            Map<PlaceholderToken, FunctionMapValue> inverse_function_map,
            JSONObject unmatched_functions,
            JSONObject unmatched_external_vars,
            Map<PlaceholderToken, MapValue> unmatched_custom_types,
            JSONObject unmatched_strings,
            Map<PlaceholderToken, MapValue> unmatched_vars,
            JSONObject unmatched_go_to_labels,
            JSONObject unmatched_custom_function_pointers,
            JSONObject unmatched_variadic_lists,
            Map<PlaceholderToken, Map<PlaceholderToken, FieldValue>> fields
    ) {
        record MapValue(String value) {
        }

        record FunctionMapValue(String name, Integer addr, boolean is_external) {
            public static FunctionMapValue fromJson(JSONObject json) {
                return new FunctionMapValue(
                        json.getString("name"),
                        json.getInt("addr"),
                        json.getBoolean("is_external")
                );
            }
        }

        record FieldValue(String value) {
        }

        public static FullFunctionMapping fromJson(JSONObject json) {
            if (json.isNull("inverse_string_map")) {
                throw new IllegalArgumentException("JSON does not contain 'inverse_string_map'");
            }
            Map<PlaceholderToken, FunctionMapValue> inverse_function_map = null;
            if (!json.isNull("inverse_function_map")) {
                inverse_function_map = json.getJSONObject("inverse_function_map").keySet()
                        .stream()
                        .collect(Collectors.toMap(
                                PlaceholderToken::new,
                                value -> FunctionMapValue.fromJson(json.getJSONObject("inverse_function_map").getJSONObject(value))
                        ));
            }
            return new FullFunctionMapping(
                    json.getJSONObject("inverse_string_map"),
                    inverse_function_map,
                    json.getJSONObject("unmatched_functions"),
                    json.getJSONObject("unmatched_external_vars"),
                    null,
                    json.getJSONObject("unmatched_strings"),
                    null,
                    json.getJSONObject("unmatched_go_to_labels"),
                    json.getJSONObject("unmatched_custom_function_pointers"),
                    json.getJSONObject("unmatched_variadic_lists"),
                    null
            );
        }
    }

    /**
     * a placeholder like `<DISASM_FUNCTION_0>`
     * @param placeHolderString
     */
    public record PlaceholderToken(String placeHolderString) {}
}
