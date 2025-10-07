package ai.reveng.toolkit.ghidra.core.services.api.types;


import org.json.JSONArray;
import org.json.JSONObject;
import java.util.List;
import java.util.ArrayList;

/**
 * Structured response for the auto unstrip endpoint
 {
 "progress": 0,
 "status": "string",
 "total_time": 0,
 "matches": [
 {
 "function_id": 0,
 "function_vaddr": 0,
 "suggested_name": "string"
 }
 ],
 "applied": true,
 "error_message": "string"
 }
 *
 */
public record AutoUnstripResponse(
        int progress,
        String status,
        int total_time,
        List<Match> matches,
        boolean applied,
        String error_message
) {

    /**
     * Represents a single match in the auto unstrip response
     */
    public record Match(
            FunctionID function_id,
            long function_vaddr,
            String suggested_name,
            String suggested_demangled_name
    ) {
        public static Match fromJSONObject(JSONObject json) {
            return new Match(
                    new FunctionID(json.getInt("function_id")),
                    json.getLong("function_vaddr"),
                    json.getString("suggested_name"),
                    json.getString("suggested_demangled_name")
            );
        }
    }

    public static AutoUnstripResponse fromJSONObject(JSONObject json) {
        List<Match> matches = new ArrayList<>();
        if (!json.isNull("matches")) {
            JSONArray matchesArray = json.getJSONArray("matches");
            for (int i = 0; i < matchesArray.length(); i++) {
                matches.add(Match.fromJSONObject(matchesArray.getJSONObject(i)));
            }
        }

        return new AutoUnstripResponse(
                json.getInt("progress"),
                json.getString("status"),
                json.getInt("total_time"),
                matches,
                json.getBoolean("applied"),
                !json.isNull("error_message") ? json.getString("error_message") : null
        );
    }
}
