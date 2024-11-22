package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIAuthenticationException;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;
import com.google.common.primitives.Bytes;
import org.json.JSONObject;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;

import static ai.reveng.toolkit.ghidra.core.services.api.Utils.mapJSONArray;
import static java.net.http.HttpClient.Version.HTTP_1_1;

/**
 * The main implementation of the RevEng HTTP API
 *
 * Design notes:
 * - every method should correspond to a single API endpoint
 * - every method should simply execute the request and return the response
 *      - i.e. no smart checks relying on other API calls to check if e.g. a binary has already been uploaded
 *
 *
 */
public class TypedApiImplementation implements TypedApiInterface {

    private final HttpClient httpClient;
    private String baseUrl;
    private String apiKey;
    Map<String, String> headers;

    public TypedApiImplementation(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl + "/";
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .version(HTTP_1_1) // by default the client would attempt HTTP2.0 which leads to weird issues
                .build();
        headers = new HashMap<>();
        headers.put("Authorization", this.apiKey);
        headers.put("User-Agent", "REAIT Java Proxy");
        // TODO: Actually implement support for some encodings and then accept them
//        headers.put("Accept-Encoding", "gzip, deflate, br");
    }


    public TypedApiImplementation(ApiInfo info){
        this(info.hostURI().toString(), info.apiKey());
    }

    public List<AnalysisResult> recentAnalyses(AnalysisStatus status, AnalysisScope scope, int number) {

        JSONObject parameters = new JSONObject();
        parameters.put("status", status.name());
        parameters.put("scope", scope.name());
        parameters.put("n", number);

        HttpRequest.Builder requestBuilder = requestBuilderForEndpoint(APIVersion.V1, "analyse/recent");
        requestBuilder
                .method("GET",HttpRequest.BodyPublishers.ofString(parameters.toString()))
                .header("Content-Type", "application/json");

        HttpRequest request = requestBuilder.build();
        var jsonResponse = sendRequest(request);

        return mapJSONArray(jsonResponse.getJSONArray("analysis"), AnalysisResult::fromJSONObject);

    }

    public BinaryHash upload(Path binPath) throws FileNotFoundException {

        File bin = binPath.toFile();

        if (!bin.exists())
            throw new FileNotFoundException("Binary to upload does not exist");

        String boundary = "------------------------" + UUID.randomUUID().toString();

        String bodyStart = "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"" + binPath.getFileName() + "\"\r\n" +
                "Content-Type: application/octet-stream\r\n\r\n";

        String bodyEnd = "\r\n--" + boundary + "--\r\n";

        // Read file bytes
        byte[] fileBytes = new byte[0];
        try {
            fileBytes = java.nio.file.Files.readAllBytes(binPath);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Combine all parts of the body
        byte[] requestBody = Bytes.concat(bodyStart.getBytes(), fileBytes, bodyEnd.getBytes());

        // Create HttpRequest
        var request = requestBuilderForEndpoint(APIVersion.V1, "upload")
                .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .build();


        return BinaryHash.fromJSONObject(sendRequest(request));
    }

    /*
    Allows you to search for specific analyses and collections.
    The query parameter follows a non standard formatting using key-pair comma seperated values.
    he base query is formatted as follows: /search?search=sha_256_hash:<hash>,binary_name:<binary_name>,tags=<tag>,collection_name:<collection_name>.
    Not all parameters are required, for example /search?search=sha_256_hash:<hash> only searches for binaries and collection with hashes like <hash>.

     */
    public List<AnalysisResult> search(BinaryHash hash) {
        return search(hash, null, null, null);
    }

    @Override
    public List<AnalysisResult> search(
            BinaryHash hash,
            String binaryName,
            Collection collection,
            AnalysisStatus state){

        JSONObject parameters = new JSONObject();
        if (hash != null){
            parameters.put("sha_256_hash", hash.sha256());
        }
        if (binaryName != null){
            parameters.put("binary_name", binaryName);
        }
        if (collection != null){
            parameters.put("collection_name", collection.collectionName());
        }
        if (state != null){
            parameters.put("state", state.name());
        }


        JSONObject json = sendRequest(
                requestBuilderForEndpoint(APIVersion.V1, "search")
                        .method("GET", HttpRequest.BodyPublishers.ofString(parameters.toString()))
                        .header("Content-Type", "application/json" )
                        .build());

        return mapJSONArray(json.getJSONArray("query_results"), AnalysisResult::fromJSONObject);
    }

    private V2Response sendVersion2Request(HttpRequest request){
        return V2Response.fromJSONObject(sendRequest(request));
    }

    private JSONObject sendRequest(HttpRequest request) throws APIAuthenticationException {
        HttpResponse<String> response = null;

        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        switch (response.statusCode()){
            case 200:
            case 201:
                return new JSONObject(response.body());
            case 401:
                throw new APIAuthenticationException(response.body());
            default:
                throw new RuntimeException("Request failed with status code: " + response.statusCode() + " and message: " + response.body());
        }
    }

    @Override
    public BinaryID analyse(AnalysisOptionsBuilder builder) {
        var request = requestBuilderForEndpoint(APIVersion.V1, "analyse/")
                .POST(HttpRequest.BodyPublishers.ofString(builder.toJSON().toString()))
                .header("Content-Type", "application/json" )
                .build();
        var jsonResponse = sendRequest(request);
        return new BinaryID(jsonResponse.getInt("binary_id"));
    }

    @Override
    public List<FunctionMatch> annSymbolsForBinary(BinaryID binID,
                                                   int resultsPerFunction,
                                                   double distance,
                                                   boolean debugMode,
                                                   List<Collection> collections
    ) {
        var params = new JSONObject();
        params.put("result_per_function", resultsPerFunction);
        params.put("distance", distance);
        params.put("debug_mode", false);

        if (collections != null){
            params.put("collection", collections.stream().map(Collection::collectionName).toList());
        }


        var request = requestBuilderForEndpoint(APIVersion.V1, "ann/symbol/" + binID.value())
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        JSONObject jsonObject = sendRequest(request);
        return mapJSONArray(jsonObject.getJSONArray("function_matches"), FunctionMatch::fromJSONObject);
    }

    @Override
    public List<FunctionMatch> annSymbolsForFunctions(List<FunctionID> fID,
                                                      int resultsPerFunction,
                                                      double distance) {

//        throw new UnsupportedOperationException("annSymbolsForFunctions not implemented yet");
        var params = new JSONObject();
        params.put("result_per_function", resultsPerFunction);
        params.put("distance", distance);
        params.put("debug_mode", false);
        params.put("function_id_list", fID.stream().map(FunctionID::value).toList());

        var request = requestBuilderForEndpoint(APIVersion.V1, "ann/symbol/batch")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        JSONObject jsonObject = sendRequest(request);
        return mapJSONArray(jsonObject.getJSONArray("function_matches"), FunctionMatch::fromJSONObject);
    }

    @Override
    public AnalysisStatus status(BinaryID binaryID) {

        var request = requestBuilderForEndpoint(APIVersion.V1, "analyse/status/" + binaryID.value())
                .GET()
                .build();
        return AnalysisStatus.valueOf(sendRequest(request).getString("status"));
    }

    @Override
    public List<FunctionInfo> getFunctionInfo(BinaryID binaryID) {
        var request = requestBuilderForEndpoint(APIVersion.V1, "analyse/functions/" + binaryID.value())
                .GET()
                .build();

        List<FunctionInfo> result = new ArrayList<>();


        return mapJSONArray(
                sendRequest(request).getJSONArray("functions"),
                FunctionInfo::fromJSONObject);
    }

    @Override
    public boolean healthStatus(){
        return health().getBoolean("success");
    }

    @Override
    public String healthMessage(){
        return health().getString("message");
    }

    @Override
    public List<Collection> collectionQuickSearch(ModelName modelName) {
        var request = requestBuilderForEndpoint(APIVersion.V1, "collections/quick/search?model_name=" + modelName.modelName())
                .build();
        var response = sendRequest(request);
        var result = new ArrayList<Collection>();
        return mapJSONArray(response.getJSONArray("collections"), o -> Collection.fromSmallJSONObject((JSONObject) o, modelName));
    }

    @Override
    public List<Collection> collectionQuickSearch(String searchTerm) {
        var request = requestBuilderForEndpoint(APIVersion.V1, "collections/quick/search?search_term=" + searchTerm)
                .build();
        var response = sendRequest(request);
        return mapJSONArray(
                response.getJSONArray("collections"),
                o -> Collection.fromSmallJSONObject(o, new ModelName("Unknown")));
    }

    @Override
    public String getAnalysisLogs(BinaryID binID) {
        var request = requestBuilderForEndpoint(APIVersion.V1, "logs/" + binID.value())
                .build();
        var response = sendRequest(request);
        return response.getString("logs");
    }

    public JSONObject health(){
        URI uri;
        try {
            uri = new URI(baseUrl + "v1");
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        var requestBuilder = HttpRequest.newBuilder(uri);
        headers.forEach(requestBuilder::header);
        requestBuilder.GET();
        try {
            var jsonResponse = sendRequest(requestBuilder.build());
            return jsonResponse;
        } catch (Exception e) {
            return new JSONObject(Map.of("success", false, "message", e.getMessage()));
        }
    }

    private HttpRequest.Builder requestBuilderForEndpoint(APIVersion version, String endpoint){
        URI uri;
        String apiVersionPath;
        if (version == APIVersion.V1){
            apiVersionPath = "v1";
        } else if (version == APIVersion.V2){
            apiVersionPath = "v2";
        } else {
            throw new RuntimeException("Unknown API version");
        }

        try {
            uri = new URI(baseUrl + apiVersionPath + "/" + endpoint);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        var requestBuilder = HttpRequest.newBuilder(uri);
        headers.forEach(requestBuilder::header);
        requestBuilder.timeout(Duration.ofSeconds(1));
        return requestBuilder;
    }
    @Override
    public List<ModelName> models(){
        JSONObject jsonResponse = sendRequest(requestBuilderForEndpoint(APIVersion.V1, "models").GET().build());

        return mapJSONArray(jsonResponse.getJSONArray("models"), o -> new ModelName(o.getString("model_name")));
    }

    @Override
    public void authenticate() throws InvalidAPIInfoException {
        var request = requestBuilderForEndpoint(APIVersion.V1, "authenticate")
                .build();
        try {
            sendRequest(request);
        } catch (APIAuthenticationException e) {
            throw new InvalidAPIInfoException("Invalid API key", e);
        }
    }

    @Override
    public boolean triggerAIDecompilationForFunctionID(FunctionID functionID) {
        JSONObject params = new JSONObject().put("function_id", functionID.value());
        HttpRequest request = requestBuilderForEndpoint(APIVersion.V2, "ai-decompilation")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        return sendVersion2Request(request).status();
    }

    @Override
    public AIDecompilationStatus pollAIDecompileStatus(FunctionID functionID) {

        HttpRequest request = requestBuilderForEndpoint(APIVersion.V2, "ai-decompilation/" + functionID.value())
                .GET()
                .build();
        return AIDecompilationStatus.fromJSONObject(sendVersion2Request(request).data());

    }
}

