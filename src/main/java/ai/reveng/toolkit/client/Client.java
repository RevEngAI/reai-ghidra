package ai.reveng.toolkit.client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import ai.reveng.toolkit.RE_AIConfig;
import ai.reveng.toolkit.exceptions.RE_AIApiException;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ai.reveng.toolkit.model.ModelInfo;

/**
 * Class that models a RevEng.AI API endpoint Client
 */
public class Client {
	private RE_AIConfig config;

	/**
	 * Create a new client from a .toml config file
	 * 
	 * @param configPath path to config file on filesystem
	 */
	public Client(String configPath) {
		this.config = new RE_AIConfig(configPath);
	}

	/**
	 * Constructor for when we have the API Key and a host url, but don't know what
	 * models are available
	 * 
	 * @param apikey
	 * @param host
	 */
	public Client(String apikey, String host) {
		this.config = new RE_AIConfig(apikey, host);
	}

	/**
	 * Convert a hashmap of params into a single string for passing in a url request
	 * 
	 * @param params hashmap of parameters
	 * @return single string that contains all the parameter
	 * @throws UnsupportedEncodingException
	 * @throws RE_AIApiException
	 */
	private String getParamsString(HashMap<String, String> params)
			throws UnsupportedEncodingException, RE_AIApiException {
		StringBuilder postData = new StringBuilder();
		for (Map.Entry<String, String> param : params.entrySet()) {
			if (postData.length() != 0)
				postData.append('&');

			postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
			postData.append('=');
			postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
		}

		return postData.toString();
	}

	/**
	 * 
	 * @return list of models available to the client
	 * @throws RE_AIApiException
	 * @throws JSONException
	 */
	public List<ModelInfo> getModels(String host) throws JSONException, RE_AIApiException {
		List<ModelInfo> models = new ArrayList<ModelInfo>();

		HashMap<String, String> headers = new HashMap<String, String>();

		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User-Agent", "Ghidra Plugin");
		try {
			HttpClient client = HttpClient.newHttpClient();

			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(new URI(host + "/models")).GET();

			headers.forEach(requestBuilder::header);

			HttpRequest request = requestBuilder.build();

			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

			System.out.println(response.body());

			JSONObject resJson = new JSONObject(response.body());

			if (resJson.has("error")) {
				throw new RE_AIApiException(resJson.getString("error"));
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
	public String analyse(String fPath, String model, String isaOptions, String platformOptions, String fileName,
			String fileOptions, Boolean dynamicExecution, String commandLineArgs)
			throws JSONException, RE_AIApiException {
		HashMap<String, String> headers = new HashMap<String, String>();
		HashMap<String, String> params = new HashMap<String, String>();

		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("Content-Type", "application/octet-stream");
		headers.put("User-Agent", "Ghidra Plugin");

		params.put("model", model);
//		params.put("platform_options", platformOptions);
//		params.put("isa_options", isaOptions);
		params.put("file_options", fileOptions);
		params.put("file_name", fileName);
		params.put("dynamic_execution", dynamicExecution.toString());
//		params.put("command_line_args", commandLineArgs);
		params.put("base_vaddr", RE_AIToolkitHelper.getInstance().getFlatAPI().getCurrentProgram().getImageBase().toString());

		String paramsString;
		// convert the hashmap params into a string of form key=value
		try {
			paramsString = this.getParamsString(params);
		} catch (UnsupportedEncodingException | RE_AIApiException e) {
			throw new RE_AIApiException("Error encoding analysis params");
		}

		System.out.format(
				"{\nmodel: %s\nplatform_options: %s\nisa_options: %s\nfile_options: %s\nfile_name: %s\ndynamic_execution: %s\ncommand_line_args: %s\n}",
				params.get("model"), params.get("platform_options"), params.get("isa_options"),
				params.get("file_options"), params.get("file_name"), params.get("dynamic_execution"),
				params.get("command_line_args"));
		System.out.println(config.getHost() + "/analyse?" + paramsString);

		try {

			HttpClient client = HttpClient.newHttpClient();

			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(new URI(config.getHost() + "/analyse?"+paramsString))
					.POST(HttpRequest.BodyPublishers.ofFile(Paths.get(fPath)));

			headers.forEach(requestBuilder::header);

			HttpRequest request = requestBuilder.build();

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			System.out.println(response.body());

			JSONObject resJson = new JSONObject(response.body());

			if (resJson.has("error")) {
				throw new RE_AIApiException(resJson.getString("error"));
			}

			return resJson.getString("sha_256_hash");

		} catch (Exception e) {
			throw new RE_AIApiException("Error sending analysis request -> " + e.getMessage());
		}
	}

	public String delete(String hash) throws RE_AIApiException {
		HashMap<String, String> headers = new HashMap<String, String>();

		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User-Agent", "Ghidra Plugin");

		HttpClient client = HttpClient.newHttpClient();

		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().DELETE()
				.uri(URI.create(config.getHost() + "/analyse/" + hash));

		headers.forEach(requestBuilder::header);

		HttpRequest request = requestBuilder.build();

		try {
			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			System.out.println(response.body());

			JSONObject resJson = new JSONObject(response.body());

			if (resJson.has("error")) {
				throw new RE_AIApiException(resJson.getString("error"));
			}

			return resJson.getString("success");
		} catch (IOException | InterruptedException e) {
			throw new RE_AIApiException(e.getMessage());
		}
	}

	public JSONArray status() throws RE_AIApiException {
		HashMap<String, String> headers = new HashMap<String, String>();

		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User-Agent", "Ghidra Plugin");
		
		try {
			HttpClient client = HttpClient.newHttpClient();

			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
					.uri(new URI(config.getHost() + "/analyse/recent?n=125")).GET();

			headers.forEach(requestBuilder::header);

			HttpRequest request = requestBuilder.build();

			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

			System.out.println(response.body());

			JSONObject resJson = new JSONObject(response.body());

			if (resJson.has("error")) {
				throw new RE_AIApiException(resJson.getString("error"));
			}

			return resJson.getJSONArray("analyses");
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}

		return null;
	}
	
	public JSONArray getBinaryEmbeddings(String hash, String model) throws RE_AIApiException {
		HashMap<String, String> headers = new HashMap<String, String>();
		HashMap<String, String> params = new HashMap<String, String>();

		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User-Agent", "Ghidra Plugin");
		
		params.put("model_name", model);
		
		String paramsString;
		// convert the hashmap params into a string of form key=value
		try {
			paramsString = this.getParamsString(params);
		} catch (UnsupportedEncodingException | RE_AIApiException e) {
			throw new RE_AIApiException("Error encoding analysis params");
		}
		
		System.out.println("Get embeddings: " + config.getHost() + "/embeddings/"+hash+"?"+paramsString);
		
		try {
			HttpClient client = HttpClient.newHttpClient();

			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
					.uri(new URI(config.getHost() + "/embeddings/"+hash+"?model_name="+model)).GET();

			headers.forEach(requestBuilder::header);

			HttpRequest request = requestBuilder.build();

			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

			System.out.println(response.body());
			
			if (response.statusCode() > 299) {
				JSONObject resJson = new JSONObject(response.body());

				if (resJson.has("error")) {
					throw new RE_AIApiException(resJson.getString("error"));
				}
				
				return null;
			}

			return new JSONArray(response.body());

		} catch (Exception e) {
			throw new RE_AIApiException(e.getMessage());
		}
	}
	
	public JSONArray visableCollections() throws RE_AIApiException {
		HashMap<String, String> headers = new HashMap<String, String>();

		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User-Agent", "Ghidra Plugin");
		
		try {
			HttpClient client = HttpClient.newHttpClient();

			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
					.uri(new URI(config.getHost() + "/collections/visible")).GET();

			headers.forEach(requestBuilder::header);

			HttpRequest request = requestBuilder.build();

			HttpResponse<String> response = client.send(request, BodyHandlers.ofString());

			System.out.println(response.body());

			JSONObject resJson = new JSONObject(response.body());

			if (resJson.has("error")) {
				throw new RE_AIApiException(resJson.getString("error"));
			}

			return resJson.getJSONArray("analyses");
		} catch (Exception e) {
			System.err.println(e.getMessage());
		}

		return null;
	}
	
	public JSONArray ann_symbols(double distance, int numNeighbours, String regex, Vector<Double> embedding, String hashes) throws RE_AIApiException {
		HashMap<String, String> headers = new HashMap<String, String>();
		
		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User-Agent", "Ghidra Plugin");
		
		String rawData = embedding.stream().map(Object::toString).collect(Collectors.joining(","));
		
		try {

			HttpClient client = HttpClient.newHttpClient();

			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(new URI(config.getHost() + "/ann/symbol?distance="+distance+"&nns="+numNeighbours+"&ignore_hashes="+hashes))
					.POST(HttpRequest.BodyPublishers.ofString("["+rawData+"]"));

			headers.forEach(requestBuilder::header);

			HttpRequest request = requestBuilder.build();

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			System.out.println(response.body());

			if (response.statusCode() > 299) {
				JSONObject resJson = new JSONObject(response.body());

				if (resJson.has("error")) {
					throw new RE_AIApiException(resJson.getString("error"));
				}
				
				return null;
			}

			return new JSONArray(response.body());

		} catch (Exception e) {
			throw new RE_AIApiException("Error sending analysis request -> " + e.getMessage());
		}
	}
	
	public String explain(String decompiledFunction) throws RE_AIApiException {
		HashMap<String, String> headers = new HashMap<String, String>();
		
		headers.put("Authorization", this.getConfig().getApiKey());
		headers.put("User-Agent", "Ghidra Plugin");
		
		try {

			HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(300)).build();

			HttpRequest.Builder requestBuilder = HttpRequest.newBuilder().uri(new URI(config.getHost() + "/explain"))
					.POST(HttpRequest.BodyPublishers.ofString(decompiledFunction));

			headers.forEach(requestBuilder::header);

			HttpRequest request = requestBuilder.build();

			HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

			System.out.println(response.body());

			if (response.statusCode() > 299) {
				JSONObject resJson = new JSONObject(response.body());

				if (resJson.has("error")) {
					throw new RE_AIApiException(resJson.getString("error"));
				}
				
				return null;
			}

			JSONObject resJson = new JSONObject(response.body());

			if (resJson.has("error")) {
				throw new RE_AIApiException(resJson.getString("error"));
			}

			return resJson.getString("explanation");

		} catch (Exception e) {
			throw new RE_AIApiException("Error sending analysis request -> " + e.getMessage());
		}
	} 

	public RE_AIConfig getConfig() {
		return config;
	}

}
