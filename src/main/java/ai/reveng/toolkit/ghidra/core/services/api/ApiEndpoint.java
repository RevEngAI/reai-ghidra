package ai.reveng.toolkit.ghidra.core.services.api;

import java.util.Map;


/**
 * Defines the valid API Endpoints for RevEng.AI
 * 
 * When adding a new endpoint with a dynamic path, enclose the dynamic part with
 * '{' and '}' for future replacement. For example /user/{userid}
 */
public enum ApiEndpoint {
	GET_MODELS("/models", "GET"),
	ECHO("/echo", "GET"),
	ANALYSE("/analyse", "POST", ApiBodyType.JSON),
	STATUS("/analyse/status/{binary_id}", "GET"),
	// the "/analyse/recent" endpoint is declared as GET in the API doc, but this is wrong!
	RECENT("/analyse/recent", "POST", ApiBodyType.JSON),
	DELETE("/analyse/{binary_id}", "DELETE"),
	EMBEDDINGS("/embeddings/{binary_id}", "GET"),
	SIGNATURE("/signature/{binary_id}", "GET"),
	EMBEDDING("/embedding/{binary_id}/{start_vaddr}", "GET"),
	LOGS("/logs/{binary_id}", "GET"),
	CVES("/cves/{binary_id}", "GET"),
	ANN_SYMBOL("/ann/symbol", "POST", ApiBodyType.EMBEDDING),
	ANN_BINARY("/ann/binary", "POST", ApiBodyType.EMBEDDING),
	SBOM("/sboms/{binary_id}", "GET"),
	MODELS("/models", "GET"),
	EXPLAIN("/explain", "POST", ApiBodyType.DECOMPILED_FUNCTION),
	COLLECTIONS("/collections", "GET"),
	UPLOAD("/upload", "POST",  ApiBodyType.FILE),

	INFO("/user/info", "GET"),
	SEARCH("/search", "GET");

	private final String pathPattern;
	private final String httpMethod;
	private final ApiBodyType bodyType;

	public ApiBodyType getBodyType() {
		return bodyType;
	}

	/**
	 * Constructor for the endpoint
	 * 
	 * @param pathPattern endpoint path with dynamic routes where applicable, e.g.
	 *                    /user/{userid}
	 * @param httpMethod  HTTP method for the endpoint - GET, POST, or DELETE
	 */
	ApiEndpoint(String pathPattern, String httpMethod, ApiBodyType bodyType) {
		this.pathPattern = pathPattern;
		this.httpMethod = httpMethod;
		this.bodyType = bodyType;
	}

	ApiEndpoint(String pathPattern, String httpMethod) {
		this(pathPattern, httpMethod, ApiBodyType.NONE);
	}

	/**
	 * Generates the path for the endpoint
	 *
	 * e.g. turns /user/{userid} into /user/123
	 * @param pathParams dynamic data that forms part of the path
	 * @return a full path that includes dynamic routes
	 */
	public String getPath(Map<String, String> pathParams) {
		String resolvedPath = pathPattern;
		for (Map.Entry<String, String> entry : pathParams.entrySet()) {
			resolvedPath = resolvedPath.replace("{" + entry.getKey() + "}", entry.getValue());
		}
		return resolvedPath;
	}

	public String getPath() {
		String resolvedPath = pathPattern;
		return resolvedPath;
	}

	public String getHttpMethod() {
		return httpMethod;
	}
}
