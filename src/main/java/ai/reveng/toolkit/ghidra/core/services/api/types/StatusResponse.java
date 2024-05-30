package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;

public class StatusResponse extends ApiResponse {

    private final StatusEnum status;

    public StatusResponse(int statusCode, String responseBody) {
        super(statusCode, responseBody);
        this.status = StatusEnum.valueOf(this.getJsonObject().getString("status"));
    }

    public StatusEnum getStatus() {
        return status;
    }
    private enum StatusEnum {
        COMPLETE("Complete"),
        PROCESSING("Processing"),
        ERROR("Error"),
        QUEUED("Queued");

        private final String status;
        StatusEnum(final String status) {
            this.status = status;
        }
    }
}


