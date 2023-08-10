package ai.reveng.reait;

import org.json.JSONObject;

/**
 * Models a response from the REAI API
 */
public class REAITResponse {
	/// HTTP Response Code
	public int responseCode;
	/// JSON Data returned by the API
	public JSONObject data;
}
