package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
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
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;

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
    private String apiVersion;
    private String apiKey;
    Map<String, String> headers;

    public TypedApiImplementation(String baseUrl, String apiKey) {
        this.baseUrl = baseUrl + "/";
        this.apiKey = apiKey;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .version(HTTP_1_1) // by default the client would attempt HTTP2.0 which leads to weird issues
                .build();
        this.apiVersion = "v1";
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

        HttpRequest.Builder requestBuilder = requestBuilderForEndpoint("analyse/recent");
        requestBuilder
                .method("GET",HttpRequest.BodyPublishers.ofString(parameters.toString()))
                .header("Content-Type", "application/json");

        HttpRequest request = requestBuilder.build();
        var jsonResponse = sendRequest(request);
        List<AnalysisResult> result = new ArrayList<>();
        jsonResponse.getJSONArray("analysis").forEach((Object o) -> {
            result.add(AnalysisResult.fromJSONObject((JSONObject) o));
        });
        return result;
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
        var request = requestBuilderForEndpoint("upload")
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
                requestBuilderForEndpoint("search")
                        .method("GET", HttpRequest.BodyPublishers.ofString(parameters.toString()))
                        .header("Content-Type", "application/json" )
                        .build());

        var result = new ArrayList<AnalysisResult>();
        json.getJSONArray("query_results").forEach((Object o) -> {
            result.add(AnalysisResult.fromJSONObject((JSONObject) o));
        });
        return result;
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
    public BinaryID analyse(BinaryHash binHash,
                            Long baseAddress,
                            List<FunctionBoundary> functionBounds, ModelName modelName) {
        JSONObject parameters = new JSONObject();
        // Probably no point making this configurable for now
        parameters.put("model_name", modelName.modelName());
//        parameters.put("platform_options", "Auto");
//        parameters.put("isa_options", "Auto");
//        parameters.put("file_options", "Auto");
//        parameters.put("dynamic_execution", false);
//        parameters.put("command_line_args", "");
//        parameters.put("priority", 0);

        // Make configurable later
//        parameters.put("tags", new JSONArray());
//        parameters.put("binary_scope", AnalysisScope.PRIVATE.name());

        // Actual arguments
        parameters.put("sha_256_hash", binHash.sha256());
//        parameters.put("debug_hash", ""); // ???


        var request = requestBuilderForEndpoint("analyse/")
                .POST(HttpRequest.BodyPublishers.ofString(parameters.toString()))
                .header("Content-Type", "application/json" )
                .build();
        var jsonResponse = sendRequest(request);
        return new BinaryID(jsonResponse.getInt("binary_id"));
    }

    @Override
    public BinaryID analyse(AnalysisOptionsBuilder builder) {
        var request = requestBuilderForEndpoint("analyse/")
                .POST(HttpRequest.BodyPublishers.ofString(builder.toJSON().toString()))
                .header("Content-Type", "application/json" )
                .build();
        var jsonResponse = sendRequest(request);
        return new BinaryID(jsonResponse.getInt("binary_id"));
    }

    @Override
    public List<FunctionMatch> annSymbolsForBinary(BinaryID binID, int resultsPerFunction, double distance) {
        var params = new JSONObject();
        params.put("result_per_function", resultsPerFunction);
        params.put("distance", distance);
        params.put("debug_mode", false);

        var request = requestBuilderForEndpoint("ann/symbol/" + binID.value())
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        JSONObject jsonObject = sendRequest(request);
        var result = new ArrayList<FunctionMatch>();
        jsonObject.getJSONArray("function_matches").forEach((Object o) -> {
            result.add(FunctionMatch.fromJSONObject((JSONObject) o));
        });
        return result;
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

        var request = requestBuilderForEndpoint("ann/symbol/batch")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        JSONObject jsonObject = sendRequest(request);
        var result = new ArrayList<FunctionMatch>();
        jsonObject.getJSONArray("function_matches").forEach((Object o) -> {
            result.add(FunctionMatch.fromJSONObject((JSONObject) o));
        });
        return result;
    }

    @Override
    public AnalysisStatus status(BinaryID binaryID) {

        var request = requestBuilderForEndpoint("analyse/status/" + binaryID.value())
                .GET()
                .build();
        return AnalysisStatus.valueOf(sendRequest(request).getString("status"));
    }

    @Override
    public List<FunctionInfo> getFunctionInfo(BinaryID binaryID) {
        var request = requestBuilderForEndpoint("analyse/functions/" + binaryID.value())
                .GET()
                .build();

        List<FunctionInfo> result = new ArrayList<>();
        sendRequest(request).getJSONArray("functions").forEach(
                o -> result.add(FunctionInfo.fromJSONObject((JSONObject) o))
        );
        return result;

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
        var request = requestBuilderForEndpoint("collections/quick/search?model_name=" + modelName.modelName())
                .build();
        var response = sendRequest(request);
        var result = new ArrayList<Collection>();
        response.getJSONArray("collections").forEach(
                o -> result.add(Collection.fromSmallJSONObject((JSONObject) o, modelName))
        );
        return result;
    }

    @Override
    public List<Collection> collectionQuickSearch(String searchTerm) {
        var request = requestBuilderForEndpoint("collections/quick/search?search_term=" + searchTerm)
                .build();
        var response = sendRequest(request);
        var result = new ArrayList<Collection>();
        response.getJSONArray("collections").forEach(
                o -> result.add(Collection.fromSmallJSONObject((JSONObject) o, new ModelName("Unknown")))
        );
        return result;
    }

    @Override
    public String getAnalysisLogs(BinaryID binID) {
        var request = requestBuilderForEndpoint("logs/" + binID.value())
                .build();
        var response = sendRequest(request);
        return response.getString("logs");
    }

    public JSONObject health(){
        URI uri;
        try {
            uri = new URI(baseUrl + apiVersion);
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

    private HttpRequest.Builder requestBuilderForEndpoint(String endpoint){
        URI uri;
        try {
            uri = new URI(baseUrl + apiVersion + "/" + endpoint);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        var requestBuilder = HttpRequest.newBuilder(uri);
        headers.forEach(requestBuilder::header);
        return requestBuilder;
    }
    @Override
    public List<ModelInfo> models(){
        JSONObject jsonResponse = sendRequest(requestBuilderForEndpoint("models").GET().build());
        List<ModelInfo> result = new ArrayList<>();
        jsonResponse.getJSONArray("models").forEach((Object o) -> {
            result.add(ModelInfo.fromJSONObject((JSONObject) o));
        });
        return result;
    }

    public boolean checkCredentials(){
        var request = requestBuilderForEndpoint("authenticate")
                .GET()
                .build();
        HttpResponse<String> response  = null;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        switch (response.statusCode()){
            case 200:

                return true;
            case 401:
                return false;
            default:
                throw new RuntimeException("Request with unexpected status code: " + response.statusCode() + " and message: " + response.body());
        }
    }
}

