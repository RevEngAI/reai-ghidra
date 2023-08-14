package ai.reveng.reait.client;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import ai.reveng.reait.REAITConfig;
import ai.reveng.reait.REAITResponse;
import ai.reveng.reait.exceptions.REAIApiException;
import ai.reveng.reait.model.ModelInfo;

/**
 * Class that models a RevEng.AI API endpoint Client
 */
public class Client {
	private static final String BOUNDARY = "Boundary" + System.currentTimeMillis();
	
	private REAITConfig config;
	
	/**
	 * Create a new client from a .toml config file
	 * @param configPath path to config file on filesystem
	 */
	public Client(String configPath) {
		this.config = new REAITConfig(configPath);
	}
	
	/**
     * Constructor for when we have the API Key and a host url, but don't know what models are available
     * @param apikey
     * @param host
     */
    public Client(String apikey, String host) {
    	this.config = new REAITConfig(apikey, host);
    }
	
	/**
	 * 
	 * @return list of models available to the client
	 * @throws REAIApiException 
	 * @throws JSONException 
	 */
	public List<ModelInfo> getModels(String host) throws JSONException, REAIApiException {
		List<ModelInfo> models = new ArrayList<ModelInfo>();
		
		HashMap<String, String> headers = new HashMap<String, String>();
		
		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User-Agent", "Ghidra Plugin");
		try {
			HttpClient client = HttpClient.newHttpClient();
			
			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
					.uri(new URI(host+"/models"))
					.GET();
			
			headers.forEach(requestBuilder::header);
			
			HttpRequest request = requestBuilder.build();
			
			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());
			
			System.out.println(response.body());
			
			JSONObject resJson = new JSONObject(response.body());
			
			if (resJson.has("error")) {
				throw new REAIApiException(resJson.getString("error"));
			}
			
			JSONArray jmodels = resJson.getJSONArray("models");
			for (int i = 0; i < jmodels.length(); i++) {
				models.add(new ModelInfo(jmodels.getString(i)));
			}
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		
		return models;
	}
	
	/// should make this return the hash
	public int analyse(String fPath, String model, String isaOptions, String platformOptions, String fileName, String fileOptions, Boolean dynamicExecution, String commandLineArgs) throws JSONException, REAIApiException {
		REAITResponse res = null;
		
		HashMap<String, String> headers = new HashMap<String, String>();
		HashMap<String, String> params = new HashMap<String, String>();
		
		headers.put("Authorization", this.getConfig().getApiKey());
		
		params.put("model", model);
		params.put("platform_options", platformOptions);
		params.put("isa_options", isaOptions);
		params.put("file_options", fileOptions);
		params.put("file_name", fileName);
		params.put("dynamic_execution", dynamicExecution.toString());
		params.put("command_line_args", commandLineArgs);
//		params.put("FILEDATA", fPath);
		
		try {
//			res = this.send("POST", "/analyse", null, headers, params);
		} catch (Exception e) {
			throw new REAIApiException("Error sending analysis request (status code: NA) -> " + e.getMessage());
		}
		
		if (res.data.has("error")) {
			throw new REAIApiException(res.data.getString("error"));
		}
		
		return 0;
	}

	public REAITConfig getConfig() {
		return config;
	}

}
