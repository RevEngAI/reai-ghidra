package ai.reveng.reait.client;


import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.net.ssl.HttpsURLConnection;

import org.json.HTTP;
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
	 * Convert a hashmap of params into a single string for passing in a url request
	 * @param params hashmap of parameters
	 * @return single string that contains all the parameter
	 * @throws UnsupportedEncodingException
	 * @throws REAIApiException 
	 */
	private String getParamsString(HashMap<String, String> params) throws UnsupportedEncodingException, REAIApiException {
		StringBuilder postData = new StringBuilder();
		for (Map.Entry<String,String> param : params.entrySet()) {
            if (postData.length() != 0) postData.append('&');
           
            postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
            postData.append('=');
            postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
        }
		
		
		
		return postData.toString();
	}
	
	/**
	 * 
	 * @return list of models available to the client
	 * @throws REAIApiException 
	 * @throws JSONException 
	 */
	public List<ModelInfo> getModels() throws JSONException, REAIApiException {
		List<ModelInfo> models = new ArrayList<ModelInfo>();
		REAITResponse res = null;
		
		HashMap<String, String> headers = new HashMap<String, String>();
		HashMap<String, String> params = new HashMap<String, String>();
		
		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User Agent", "Ghidra Plugin");
		try {
			res = this.send("GET", "/models", null, headers, params);
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}
		
		if (res.data.has("error")) {
			throw new REAIApiException(res.data.getString("error"));
		}
		
		JSONArray jmodels = res.data.getJSONArray("models");
		for (int i = 0; i < jmodels.length(); i++) {
			models.add(new ModelInfo(jmodels.getString(i)));
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
			res = this.send("POST", "/analyse", null, headers, params);
		} catch (Exception e) {
			throw new REAIApiException("Error sending analysis request (status code: NA) -> " + e.getMessage());
		}
		
		if (res.data.has("error")) {
			throw new REAIApiException(res.data.getString("error"));
		}
		
		return 0;
	}
	
	/**
	 * Send a request to the RevEng.AI API and get the result
	 * @param requestType HTTP request type ["GET", "POST", "DELETE"]
	 * @param endPoint API endpoint for the request
	 * @param data JSON object containing the data for the endpoint
	 * @param headers HTTP headers for the request, one of which must be Authorization: <api_key>
	 * @param params HTTP parameters for the request
	 * @return REAITResponse that contains the status code, and a JSONObject with any relevent data
	 * @throws Exception 
	 * @see REAITResponse
	 */
	private REAITResponse send(String requestType, String endPoint, JSONObject data, HashMap<String, String> headers, HashMap<String, String> params) throws Exception {
		URL url = null;
		HttpsURLConnection conn;
		String paramsString = null;
		REAITResponse res = new REAITResponse();
		HttpClient httpClient = HttpClient.newHttpClient();
		HttpRequest.Builder requestBuilder;
		
		// convert the hashmap params into a string of form key=value
		if (params.size() > 0) {
			paramsString = this.getParamsString(params);		
		}
		
		String rtype = requestType.toUpperCase();
		if (rtype == "GET") {
			// params in a get request are put in the url
			conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod("GET");
			
		} else if (rtype == "POST") {
			url = new URI(this.config.getHost() + endPoint).toURL();
			requestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(this.config.getHost() + endPoint));
			/* 
			 * if we need to post a file, read the file and then delete it
			 * as the builder readers everything in and we don't want duplications
			 */
			String requestBody;
			if (params.containsKey("FILEDATA")) {
				Path fileToUpload = Paths.get(params.get("FILEDATA"));
				headers.remove("FILEDATA");
				requestBody = formMultipartBody(params, fileToUpload, "AnalyseFile", params.get("file_name"));
				requestBuilder.POST(HttpRequest.BodyPublishers.ofString(requestBody))
					.header("Content-Type", "multipart/form-data; boundary=" + BOUNDARY);
			} else {
				String formData = generateFormData(params);
				requestBuilder.POST(HttpRequest.BodyPublishers.ofString(formData))
					.header("Content-Type", "application/x-www-form-urlencoded");
			}
			
			headers.forEach(requestBuilder::header);
			
			HttpRequest request = requestBuilder.build();
			
			HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Handle the response as needed
            System.out.println("Response Code: " + response.statusCode());
            System.out.println("Response Body: " + response.body());

	        // check for a generic DATA key and dump the value in the body
		} else if (rtype == "DELETE") {
			url = new URI(this.config.getHost() + endPoint).toURL();
			
			conn = (HttpsURLConnection) url.openConnection();
			conn.setRequestMethod("DELETE");
		} else
			throw new IOException("Invalid Request Type");
		
		return null;
		
//		res.responseCode = conn.getResponseCode();
//		
//		Reader streamReader = null;
//
//		// read the response on a failed request
//		if (res.responseCode > 299) {
//		    streamReader = new InputStreamReader(conn.getErrorStream());
//		} else {
//		    streamReader = new InputStreamReader(conn.getInputStream());
//		}
//		
//		// read the response
//		BufferedReader in = new BufferedReader(streamReader);
//		String inputLine;
//		StringBuffer content = new StringBuffer();
//		while ((inputLine = in.readLine()) != null) {
//			content.append(inputLine + "\n");
//		}
//		in.close();
//		
//		res.data = new JSONObject(content.toString());
//
//		conn.disconnect();
//		return res;
	}
	
	private static String generateFormData(Map<String, String> data) {
        return data.entrySet().stream()
                .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
                .collect(Collectors.joining("&"));
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
	
	private static String formMultipartBody(Map<String, String> parameters, Path file, String fileFormName, String fileName) {
        StringBuilder builder = new StringBuilder();

        // Append form fields
        for (Map.Entry<String, String> param : parameters.entrySet()) {
            builder.append("--").append(BOUNDARY).append("\r\n");
            builder.append("Content-Disposition: form-data; name=\"").append(param.getKey()).append("\"\r\n\r\n");
            builder.append(param.getValue()).append("\r\n");
        }

        // Append file
        builder.append("--").append(BOUNDARY).append("\r\n");
        builder.append("Content-Disposition: form-data; name=\"").append(fileFormName).append("\"; filename=\"").append(fileName).append("\"\r\n\r\n");
        try {
            builder.append(Files.readString(file)).append("\r\n");  // assuming text file; you'd handle binary differently
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        builder.append("--").append(BOUNDARY).append("--\r\n");

        return builder.toString();
    }

	public REAITConfig getConfig() {
		return config;
	}

}
