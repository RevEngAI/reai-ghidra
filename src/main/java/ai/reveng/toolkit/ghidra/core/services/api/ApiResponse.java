package ai.reveng.toolkit.ghidra.core.services.api;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

/**
 * Models a response from the API
 * 
 * Attempts to parse the response body as JSON, but will just null the result if invalid
 */
public class ApiResponse {
	private int statusCode;
	private String responseBody;
	private JSONObject jsonObject;
	private JSONArray jsonArray;

	public ApiResponse(int statusCode, String responseBody) {
		this.statusCode = statusCode;
		this.responseBody = responseBody;

		// Try parsing as JSON Object
		try {
			this.jsonObject = new JSONObject(responseBody);
		} catch (JSONException e) {
			this.jsonObject = null;
		}

		// Try parsing as JSON Array
		try {
			this.jsonArray = new JSONArray(responseBody);
		} catch (JSONException e) {
			this.jsonArray = null;
		}
	}

	public int getStatusCode() {
		return statusCode;
	}

	public String getResponseBody() {
		return responseBody;
	}

	public JSONObject getJsonObject() {
		return jsonObject;
	}

	public JSONArray getJsonArray() {
		return jsonArray;
	}

	@Override
	public String toString() {
		return "HttpResponseWrapper{" + "statusCode=" + statusCode + ", responseBody='" + responseBody + '\''
				+ ", jsonObject=" + jsonObject + ", jsonArray=" + jsonArray + '}';
	}
}
