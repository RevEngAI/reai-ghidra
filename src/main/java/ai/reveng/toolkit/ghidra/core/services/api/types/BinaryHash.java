package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

/*
 * Data type for all reveng API responses or parameters that are a binary hash (as returned by the upload method)
 * The existence of a BinaryHash implies that there is a binary with this hash on the server!
 *
 * This could later be enforced via package private methods
 *
 */
public record BinaryHash(String sha256) {
    public static BinaryHash fromJsonString(String json) {
        return new BinaryHash(new JSONObject(json).getString("sha_256_hash"));
    }
    public static BinaryHash fromJSONObject(JSONObject json) {
        return new BinaryHash(json.getString("sha_256_hash"));
    }

}