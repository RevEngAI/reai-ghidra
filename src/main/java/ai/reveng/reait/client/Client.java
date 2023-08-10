package ai.reveng.reait.client;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.json.JSONArray;
import org.json.JSONObject;

import ai.reveng.reait.REAITConfig;
import ai.reveng.reait.REAITResponse;
import ai.reveng.reait.model.ModelInfo;

public class Client {
	private REAITConfig config;
	
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
	 * Convert a hashmap of params into a single string for passing in a url request
	 * @param params hashmap of parameters
	 * @return single string that contains all the parameter
	 * @throws UnsupportedEncodingException
	 */
	private String getParamsString(HashMap<String, String> params) throws UnsupportedEncodingException {
		StringBuilder postData = new StringBuilder();
		for (Map.Entry<String,String> param : params.entrySet()) {
            if (postData.length() != 0) postData.append('&');
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
		return postData.toString();
	}
	
	public List<ModelInfo> getModels() {
		List<ModelInfo> models = new ArrayList<ModelInfo>();
		REAITResponse res = null;
		
		HashMap<String, String> headers = new HashMap<String, String>();
		HashMap<String, String> params = new HashMap<String, String>();
		
		headers.put("Authorization", this.getConfig().getApiKey());
		try {
			res = this.send("GET", "/models", null, headers, params);
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		
		JSONArray jmodels = res.data.getJSONArray("models");
		for (int i = 0; i < jmodels.length(); i++) {
			models.add(new ModelInfo(jmodels.getString(i)));
		}
		return models;
	}
	
	public REAITResponse send(String requestType, String endPoint, JSONObject data, HashMap<String, String> headers, HashMap<String, String> params) throws IOException, URISyntaxException {
		URL url;
		HttpsURLConnection conn;
		String paramsString = null;
		REAITResponse res = new REAITResponse();
		
		// convert the hashmap params into a string of form key=value
		if (params.size() > 0) {
			paramsString = this.getParamsString(params);
		}
		
		String rtype = requestType.toUpperCase();
		if (rtype == "GET") {
			// params in a get request are put in the url
			url = new URI(this.config.getHost() + endPoint + "?" + paramsString).toURL();
			conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			
		} else if (rtype == "POST") {
			url = new URI(this.config.getHost() + endPoint).toURL();
			conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod("POST");
			// params in a post request are placed in the body
			byte[] postDataBytes = paramsString.toString().getBytes("UTF-8");
			conn.setDoOutput(true);
	        conn.getOutputStream().write(postDataBytes);
		} else if (rtype == "DELETE") {
			url = new URI(this.config.getHost() + endPoint).toURL();
			
			conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod("DELETE");
		} else
			throw new IOException("Invalid Request Type");
		
		for (Map.Entry<String, String> header : headers.entrySet()) {
			String key = header.getKey();
			String value = header.getValue();	
			conn.setRequestProperty(key, value);
		}
		
		res.responseCode = conn.getResponseCode();
		
		Reader streamReader = null;

		// read the response on a failed request
		if (res.responseCode > 299) {
		    streamReader = new InputStreamReader(conn.getErrorStream());
		} else {
		    streamReader = new InputStreamReader(conn.getInputStream());
		}
		
		// read the response
		BufferedReader in = new BufferedReader(streamReader);
		String inputLine;
		StringBuffer content = new StringBuffer();
		while ((inputLine = in.readLine()) != null) {
			content.append(inputLine + "\n");
		}
		in.close();
		
		res.data = new JSONObject(content.toString());

		conn.disconnect();
		return res;
	}

	public REAITConfig getConfig() {
		return config;
	}

}
