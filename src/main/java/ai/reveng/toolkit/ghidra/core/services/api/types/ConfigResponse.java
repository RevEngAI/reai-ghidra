package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

import java.util.List;

/**
 * {
 * "success": true,
 * "max_file_size": 6291456,
 * "valid_models": [
 * "binnet-0.3-x86"
 * ],
 * "isa_options": [
 * "Auto",
 * "x86",
 * "x86_64"
 * ],
 * "file_options": [
 * "Auto",
 * "PE",
 * "ELF",
 * "RAW",
 * "EXE",
 * "dll",
 * "Mach-O"
 * ],
 * "platform_options": [
 * "Auto",
 * "windows",
 * "linux",
 * "android",
 * "macos"
 * ],
 * "analysis_status_conditions": [
 * "Complete",
 * "Error",
 * "Processing",
 * "Queued",
 * "All"
 * ],
 * "analysis_scope_conditions": [
 * "PUBLIC",
 * "PRIVATE",
 * "ALL"
 * ]
 * }
 */
public record ConfigResponse(
        boolean success,
        int max_file_size,
        List<String> valid_models,
        List<String> isa_options,
        List<String> file_options,
        List<String> platform_options,
        List<String> analysis_status_conditions,
        List<String> analysis_scope_conditions
) {
    public static ConfigResponse fromJSONObject(JSONObject json) {
        throw new UnsupportedOperationException("Not implemented yet.");
//        return new ConfigResponse(
//                json.getBoolean("success"),
//                json.getInt("max_file_size"),
//                json.getJSONArray("valid_models").toList(),
//                json.getJSONArray("isa_options").toList(),
//                json.getJSONArray("file_options").toList(),
//                json.getJSONArray("platform_options").toList(),
//                json.getJSONArray("analysis_status_conditions").toList(),
//                json.getJSONArray("analysis_scope_conditions").toList()
//        );
    }

}
