package ai.reveng.toolkit.ghidra.core.services.api;

import java.util.Map;

/**
 * Defines the valid API Endpoints for RevEng.AI
 * 
 * When adding a new endpoint with a dynamic path, enclose the dynamic part with
 * '{' and '}' for future replacement. For example /user/{userid}
 */
public enum ApiEndpoint {
	GET_MODELS("/models", "GET"), ECHO("/echo", "GET"), ANALYSE("/analyse", "POST"),
	STATUS("/analyse/status/{sha_256_hash}", "GET"), DELETE("/analyse/{sha_256_hash}", "DELETE"),
	EMBEDDINGS("/embeddings/{sha_256_hash}", "GET"), SIGNATURE("/signature/{sha_256_hash}", "GET"),
	EMBEDDING("/embedding/{sha_256_hash}/{start_vaddr}", "GET"), LOGS("/logs/{sha_256_hash}", "GET"),
	CVES("/cves/{sha_256_hash}", "GET"), ANN_SYMBOL("/ann/symbol", "POST"), ANN_BINARY("/ann/binary", "POST"),
	SBOM("/sboms/{sha_256_hash}", "GET"), MODELS("/models", "GET"), EXPLAIN("/explain", "POST"),
	COLLECTIONS("/collections", "GET"), UPLOAD("/upload", "POST");

	private final String pathPattern;
	private final String httpMethod;

	/**
	 * Constructor for the endpoint
	 * 
	 * @param pathPattern endpoint path with dynamic routes where applicable, e.g.
	 *                    /user/{userid}
	 * @param httpMethod  HTTP method for the endpoint - GET, POST, or DELETE
	 */
	ApiEndpoint(String pathPattern, String httpMethod) {
		this.pathPattern = pathPattern;
		this.httpMethod = httpMethod;
	}

	/**
	 * Generates the path for the endpoint
	 * 
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

	public String getHttpMethod() {
		return httpMethod;
	}
}
