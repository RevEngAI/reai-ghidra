package ai.reveng.toolkit.ghidra.core.services.api.types;

import org.json.JSONObject;

/**
 * Example in data_types_batch_response.json
 */
public record FunctionDataTypeStatusBatch(
        int totalCount,
        int totalDataTypesCount,
        FunctionDataTypeStatus[] dataTypes
) {

    public static FunctionDataTypeStatusBatch fromJson(JSONObject json) {
        int totalCount = json.getInt("total_count");
        int totalDataTypesCount = json.getInt("total_data_types_count");
        var dataTypesJson = json.getJSONArray("items");
        FunctionDataTypeStatus[] dataTypes = new FunctionDataTypeStatus[dataTypesJson.length()];
        for (int i = 0; i < dataTypesJson.length(); i++) {
            dataTypes[i] = FunctionDataTypeStatus.fromJson(dataTypesJson.getJSONObject(i));
        }
        return new FunctionDataTypeStatusBatch(totalCount, totalDataTypesCount, dataTypes);
    }

    public FunctionDataTypeStatus statusForFunction(FunctionID functionID) {
        for (FunctionDataTypeStatus status : dataTypes) {
            if (status.functionID().equals(functionID)) {
                return status;
            }
        }
        throw new IllegalArgumentException("FunctionID not found in data types list: " + functionID);
    }
}
