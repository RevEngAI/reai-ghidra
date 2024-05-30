package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;

public class HashResponse extends ApiResponse {

    private final String hash;

    public HashResponse(int statusCode, String responseBody) {
        super(statusCode, responseBody);
        this.hash = this.getJsonObject().getString("sha_256_hash");
    }

    public String getHash() {
        return hash;
    }
}

