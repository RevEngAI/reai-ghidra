package ai.reveng.toolkit.ghidra.core.services.api;


import org.json.JSONObject;

import java.util.List;

import static ai.reveng.toolkit.ghidra.core.services.api.Utils.mapJSONArray;

/**
 * Structured Response from any V2 Endpoint
 * {
 *   "status": true,
 *   "data": {
 *     "queued": true,
 *     "reference": "404f60e6-7b1d-4adf-951c-710925422bd8"
 *   },
 *   "message": null,
 *   "errors": null,
 *   "meta": {
 *     "pagination": null
 *   }
 * }
 *
 */
public record V2Response(
        boolean status,
        // Either a JSONObject or JSONArray
        Object data,
        String message,
        List<APIError> errors,
        JSONObject meta

) {


    public static V2Response fromJSONObject(JSONObject json) {
        return new V2Response(
                json.getBoolean("status"),
                !json.isNull("data") ? json.get("data") : null,
                !json.isNull("message") ? json.getString("message") : null,
                !json.isNull("errors") ? mapJSONArray(json.getJSONArray("errors"), APIError::fromJSONObject) : null,
                json.getJSONObject("meta")
        );
    }

    public JSONObject getJsonData() {
        return (JSONObject) data;
    }
}
