package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.IOException;
import java.util.Map;

/**
 * Interface for sending HTTP Requests to the RevEng.AI enpoints
 */
public interface IApiRequester {
	/**
	 * 
	 * @param endpoint    path of the endpoint
	 * @param pathParams  any dynamic data required to generate the path
	 * @param queryParams HTTP parameters for the endpoint
	 * @param body        data for the request
	 * @param bodyType    the type of the data, e.g. FILE, JSON
	 * @param headers     HTTP Headers required for the endpoint request
	 * @return ApiResponse object that contains the status code, and response body
	 * @throws IOException when an IO Exception occurs
	 * @throws InterruptedException when an InterruptedException occurs
	 */
	ApiResponse send(ApiEndpoint endpoint, Map<String, String> pathParams, Map<String, String> queryParams, Object body,
			ApiBodyType bodyType, Map<String, String> headers) throws IOException, InterruptedException;
}
