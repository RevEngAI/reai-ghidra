package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import ai.reveng.toolkit.ghidra.core.services.api.types.LegacyCollection;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIAuthenticationException;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIConflictException;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;
import com.google.common.primitives.Bytes;
import ghidra.util.Msg;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.annotation.Nullable;
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
    public List<LegacyAnalysisResult> search(BinaryHash hash) {
        return search(hash, null, null, null);
    }

    @Override
    public List<LegacyAnalysisResult> search(
            BinaryHash hash,
            String binaryName,
            LegacyCollection collection,
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

        return mapJSONArray(json.getJSONArray("query_results"), LegacyAnalysisResult::fromJSONObject);
    }

    private V2Response sendVersion2Request(HttpRequest request){
        return V2Response.fromJSONObject(sendRequest(request));
    }

    private JSONObject sendRequest(HttpRequest request) throws APIAuthenticationException {
        Msg.info(this, "Sending request to: " + request.uri());
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
            case 404:
                return new JSONObject(response.body());
            case 401:
                throw new APIAuthenticationException(response.body());
            case 409:
                throw new APIConflictException(response.body());
            default:
                var errorMsg = "Request to %s failed with status code: %s and message: %s".formatted(request.uri(), response.statusCode(), response.body());
                Msg.showError(this, null, "Request failed with status code: " + response.statusCode(), errorMsg);
                throw new RuntimeException(errorMsg);
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
                                                      @Nullable List<CollectionID> collections,
                                                      @Nullable List<AnalysisID> analysisIDs,
                                                      double distance, boolean debug
    ) {

        var params = new JSONObject();
        params.put("result_per_function", resultsPerFunction);
        params.put("distance", distance);
        params.put("debug_mode", debug);
        params.put("function_id_list", fID.stream().map(FunctionID::value).toList());
        if (collections != null && !collections.isEmpty()){
            params.put("collection_search_list", collections.stream().map(CollectionID::id).toList());
        }
        if (analysisIDs != null && !analysisIDs.isEmpty()){
            params.put("binaries_search_list", analysisIDs.stream().map(AnalysisID::id).toList());
        }

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
    public AnalysisStatus status(AnalysisID analysisID) {
        var request = requestBuilderForEndpoint(APIVersion.V2, "analyses/%s/status".formatted(analysisID.id()))
                .GET()
                .build();
        return AnalysisStatus.valueOf(sendVersion2Request(request).getJsonData().getString("analysis_status"));
    }

    @Override
    public List<FunctionInfo> getFunctionInfo(BinaryID binaryID) {
        var request = requestBuilderForEndpoint(APIVersion.V1, "analyse/functions/" + binaryID.value())
                .GET()
                .build();

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

    private String queryParams(Map<String, String> params){
        return "?" + params.entrySet().stream()
                .filter(e -> e.getValue() != null)
                .map(e -> e.getKey() + "=" + e.getValue())
                .reduce((a, b) -> a + "&" + b)
                .orElse("");
    }
    /**
     * <a href="https://api.reveng.ai/v2/docs#tag/Collections/operation/list_collections_v2_collections_get">...</a>
     *
     * Parameters are passed via query parameters
     * @param searchTerm
     * @return
     */
    @Override
    public List<Collection> searchCollections(String searchTerm,
                                                    @Nullable List<SearchFilter> filter,
                                                    int limit,
                                                    int offset,
                                                    @Nullable CollectionResultOrder orderBy,
                                                    @Nullable OrderDirection order
    ){
        Map<String, String> params = new HashMap<>();
        params.put("search_term", searchTerm);
        params.put("limit", String.valueOf(limit));
        params.put("offset", String.valueOf(offset));
        if (filter != null){
            params.put("filter", filter.stream().map(SearchFilter::name).reduce( (a, b) -> a + "," + b).orElse(null));
        }
        if (orderBy != null){
            params.put("order_by", orderBy.name());
        }
        if (order != null){
            params.put("order", order.name());
        }
        params.put("limit", String.valueOf(limit));

        var request = requestBuilderForEndpoint(APIVersion.V2, "collections", queryParams(params))
                .timeout(Duration.ofSeconds(10))
                .method("GET", HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        var response = sendVersion2Request(request);
        var resultAsLegacyCollections =  mapJSONArray(response.getJsonData().getJSONArray("results"), LegacyCollection::fromJSONObject);
        return resultAsLegacyCollections.stream().map( legacyCollection -> this.getCollectionInfo(legacyCollection.collectionID())).toList();
    }

    /**
     * <a href="https://api.reveng.ai/v2/docs#tag/Platform-Search/operation/search_binaries_v2_search_binaries_get">Binaries Search</a>
     * @param searchTerm
     * @return
     */
    @Override
    public List<AnalysisID> searchBinaries(String searchTerm) {
        Map<String, String> params = new HashMap<>();
        params.put("partial_name", searchTerm);
        params.put("page_size", "20");
//        params.put("page", String.valueOf(offset));

        var request = requestBuilderForEndpoint(APIVersion.V2, "search", "binaries", queryParams(params))
                .timeout(Duration.ofSeconds(10))
                .method("GET", HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();

        var response = sendVersion2Request(request);
        var resultIDs =  mapJSONArray(response.getJsonData().getJSONArray("results"), entry -> ((JSONObject) entry).getInt("analysis_id"))
                .stream().map(AnalysisID::new).toList();
        return resultIDs;
    }

    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        var request = requestBuilderForEndpoint(APIVersion.V2, "analyses", String.valueOf(analysisID.id()), "logs")
                .build();
        JSONObject response = sendVersion2Request(request).getJsonData();
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

    private HttpRequest.Builder requestBuilderForEndpoint(APIVersion version, String... endpointPaths){
        URI uri;
        String apiVersionPath;
        if (version == APIVersion.V1){
            apiVersionPath = "v1";
        } else if (version == APIVersion.V2){
            apiVersionPath = "v2";
        } else {
            throw new RuntimeException("Unknown API version");
        }
        String endpoint = String.join("/", endpointPaths).replace("/?", "?").replace("?/", "?");

        try {
            uri = new URI(baseUrl + apiVersionPath + "/" + endpoint);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        var requestBuilder = HttpRequest.newBuilder(uri);
        headers.forEach(requestBuilder::header);
        requestBuilder.timeout(Duration.ofSeconds(20));
        return requestBuilder;
    }
    @Override
    public List<ModelName> models(){
        JSONObject jsonResponse = sendRequest(requestBuilderForEndpoint(APIVersion.V1, "models").GET().build());

        return mapJSONArray(jsonResponse.getJSONArray("models"), o -> new ModelName(o.getString("model_name")));
    }

    /**
     * <a href="https://api.reveng.ai/v2/docs#tag/Analysis-Management/operation/get_analysis_id_v2_analyses_lookup__binary_id__get">...</a>
     *
     * @param binaryID the binary id to look up
     * @return the analysis id
     */
    @Override
    public AnalysisID getAnalysisIDfromBinaryID(BinaryID binaryID){
        JSONObject response = sendRequest(requestBuilderForEndpoint(APIVersion.V2, "analyses/lookup/" + binaryID.value())
                .GET()
                .build());

        return new AnalysisID(response.getInt("analysis_id"));
    }

    /**
     * Triggers the generation of function data types for a provided list of functions
     * <a href="https://api.reveng.ai/v2/docs#tag/Function-Overview/operation/generate_function_datatypes_v2_analyses__analysis_id__info_functions_data_types_post">...</a>
     * https://api.reveng.ai/v2/analyses/{analysis_id}/info/functions/data_types
     * @param functionIDS
     * @return
     */
    @Override
    public DataTypeList generateFunctionDataTypes(AnalysisID analysisID, List<FunctionID> functionIDS) throws APIConflictException{
        JSONObject params = new JSONObject();
        params.put("function_ids", functionIDS.stream().map(FunctionID::value).toList());

        var request = requestBuilderForEndpoint(APIVersion.V2, "analyses/%s/info/functions/data_types".formatted(analysisID.id()))
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();

        var response = sendVersion2Request(request);
        return DataTypeList.fromJson(response.getJsonData().getJSONObject("data_types_list"));
    }

    @Override
    public DataTypeList getFunctionDataTypes(List<FunctionID> functionIDS) {
        String queryString = functionIDS.stream().map( f -> "function_ids=" + f.value() ).reduce((a, b) -> a + "&" + b).orElseThrow();

        var request = requestBuilderForEndpoint(APIVersion.V2, "functions", "data_types?", queryString)
                .GET()
                .header("Content-Type", "application/json" )
                .build();
        var response = sendVersion2Request(request);
        return DataTypeList.fromJson(response.getJsonData());
    }

    @Override
    public Optional<FunctionDataTypeStatus> getFunctionDataTypes(AnalysisID analysisID, FunctionID functionID) {
        // https://api.reveng.ai/v2/analyses/{analysis_id}/info/functions/{function_id}/data_types
        var request = requestBuilderForEndpoint(APIVersion.V2, "analyses/%s/info/functions/%s/data_types".formatted(analysisID.id(), functionID.value()))
                .GET()
                .header("Content-Type", "application/json" )
                .build();
        var response = sendVersion2Request(request);
        if (response.errors() == null){
            return Optional.of(FunctionDataTypeStatus.fromJson(response.getJsonData()));
        } else {
            return Optional.empty();
        }
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

        HttpRequest request = requestBuilderForEndpoint(APIVersion.V2, "ai-decompilation/" + functionID.value(), "?summarise=true")
                .GET()
                .build();
        return AIDecompilationStatus.fromJSONObject(sendVersion2Request(request).getJsonData());

    }

    /**
     * https://api.reveng.ai/redoc#tag/Analysis-Info/operation/batch_rename_function_v1_functions_batch_rename_post
     * @param renameDict
     *
     * ```
     * {
     *   "new_name_mapping": [
     *     {
     *       "function_id": 3624718,
     *       "function_name": "test_batch_rename_3"
     *     },
     *     {
     *       "function_id": 3624696,
     *       "function_name": "test_batch_rename_4"
     *     }
     *   ]
     * }
     * ```
     *
     */
    @Override
    public void renameFunctions(Map<FunctionID, String> renameDict) {
        JSONObject params = new JSONObject();
        var newNames = new ArrayList<JSONObject>();
        for (var entry : renameDict.entrySet()){
            newNames.add(new JSONObject()
                    .put("function_id", entry.getKey().value())
                    .put("function_name", entry.getValue()));
        }
        params.put("new_name_mapping", newNames);

        HttpRequest request = requestBuilderForEndpoint(APIVersion.V1, "functions/batch/rename")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        sendRequest(request);

    }

    @Override
    public FunctionNameScore getNameScore(FunctionMatch match) {
        return getNameScores(List.of(match), false).get(0);
    }

    /**
     * <a href="https://api.reveng.ai/v2/docs#tag/Collections/operation/get_collection_v2_collections__collection_id__get">Collection Info</a>
     *
     * @param id
     * @return
     */
    @Override
    public Collection getCollectionInfo(CollectionID id) {
        var request = requestBuilderForEndpoint(APIVersion.V2, "collections", String.valueOf(id.id()))
                .GET()
                .build();
        var response = sendVersion2Request(request);
        return Collection.fromJSONObject(response.getJsonData());
    }

    /**
     * https://api.reveng.ai/v2/docs#tag/Confidence-Scores/operation/function_threat_score_v2_confidence_functions_threat_score_post
     */
    @Override
    public List<FunctionNameScore> getNameScores(List<FunctionMatch> matches, Boolean isDebug) {
        JSONObject params = new JSONObject();
        params.put("is_debug", isDebug);
        var functions = new ArrayList<JSONObject>();
        for (var match : matches){
            functions.add(new JSONObject()
                    // The id of the original function that matches were searched for
                    .put("function_id", match.origin_function_id().value())
                    // The name of the nearest neighbor function for which we want the score
                    .put("function_name", match.nearest_neighbor_function_name()));
        }
        params.put("functions", functions);

        HttpRequest request = requestBuilderForEndpoint(APIVersion.V2, "confidence", "functions", "name_score")
                .POST(HttpRequest.BodyPublishers.ofString(params.toString()))
                .header("Content-Type", "application/json" )
                .build();
        JSONArray responseData = (JSONArray) sendVersion2Request(request).data();
        return mapJSONArray(responseData, FunctionNameScore::fromJSONObject);
    }

    /**
     *
     * @param id
     * @return
     */
    @Override
    public AnalysisResult getInfoForAnalysis(AnalysisID id) {
        var request = requestBuilderForEndpoint(APIVersion.V2, "analyses", String.valueOf(id.id()))
                .GET()
                .build();
        var response = sendVersion2Request(request);
        return AnalysisResult.fromJSONObject(this, response.getJsonData());
    }

    /**
     * https://api.reveng.ai/redoc#tag/Functions-overview/operation/function_detail_v2_functions__function_id__get
     * @param id
     * @return
     */
    @Override
    public FunctionDetails getFunctionDetails(FunctionID id) {
        var request = requestBuilderForEndpoint(APIVersion.V2, "functions", String.valueOf(id.value()))
                .GET()
                .build();
        var response = sendVersion2Request(request);
        return FunctionDetails.fromJSON(response.getJsonData());
    }

}

