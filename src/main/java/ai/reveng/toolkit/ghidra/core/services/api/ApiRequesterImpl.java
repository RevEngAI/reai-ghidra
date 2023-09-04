package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.json.JSONObject;

/**
 * Implements behaviour for the IApiRequester Interface
 */
public class ApiRequesterImpl implements IApiRequester {

	private HttpClient httpClient;
	private String baseUrl;

	public ApiRequesterImpl(String baseUrl) {
		this.httpClient = HttpClient.newHttpClient();
		this.baseUrl = baseUrl;
	}

	@Override
	public ApiResponse send(ApiEndpoint endpoint, Map<String, String> pathParams, Map<String, String> queryParams,
			Object body, ApiBodyType bodyType, Map<String, String> headers) throws IOException, InterruptedException {

		String dynamicPath = (pathParams != null) ? endpoint.getPath(pathParams) : endpoint.getPath(new HashMap<>());
		String queryString = (queryParams != null) ? buildQueryString(queryParams) : "";
		URI uri;
		try {
			uri = new URI(baseUrl + dynamicPath + queryString);
		} catch (URISyntaxException e) {
			throw new RuntimeException("Error forming URI", e);
		}

		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri);

		switch (endpoint.getHttpMethod()) {
		case "GET":
			requestBuilder.GET();
			break;
		case "POST":
			if (body != null) {
				switch (bodyType) {
				case JSON:
					String jsonPayload = new JSONObject((Map<?, ?>) body).toString();
					requestBuilder.POST(HttpRequest.BodyPublishers.ofString(jsonPayload)).header("Content-Type",
							"application/json");
					break;
				case FILE:
					requestBuilder.POST(HttpRequest.BodyPublishers.ofFile((Path) body)).header("Content-Type",
							"application/octet-stream");
					break;
				case EMBEDDING:
					String rawData = ((List<Double>) body).stream().map(Object::toString).collect(Collectors.joining(","));
					requestBuilder.POST(HttpRequest.BodyPublishers.ofString("["+rawData+"]"));
					break;
				default:
					break;
				}
			}
			break;
		case "DELETE":
			requestBuilder.DELETE();
			break;
		// ... other methods ...
		}

		if (headers != null) {
			headers.forEach(requestBuilder::header);
		}

		HttpRequest request = requestBuilder.build();
		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
		return new ApiResponse(response.statusCode(), response.body());
	}

	/**
	 * Create a query string that can be appended to a URL
	 * @param queryParams parameters to encode
	 * @return string in the form ?{key}={value}(&)...
	 */
	private String buildQueryString(Map<String, String> queryParams) {
		if (queryParams == null || queryParams.isEmpty()) {
			return "";
		}

		StringBuilder queryString = new StringBuilder("?");

		// Stream through the map, URL encode each key and value pair, and then collect
		// them
		queryString.append(queryParams.entrySet().stream().map(entry -> {
			try {
				return URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8.name()) + "="
						+ URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name());
			} catch (UnsupportedEncodingException e) {
				throw new RuntimeException(e); // This shouldn't happen with UTF-8
			}
		}).collect(Collectors.joining("&")));

		return queryString.toString();
	}

}