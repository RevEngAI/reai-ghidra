package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;


/**
 * Implements a Ghidra compatible interface on top of the RevEngAI REST API
 * The idea is that all other plugin and UI code can simply use this service to interact with the API
 * by directly providing Ghidra objects. This service then internally maps them to the API objects
 *
 * All methods are blocking, so they should be wrapped in Tasks if async behavior is needed
 *
 * This is used in the rest of the plugin(s) as a Ghidra Service, but doesn't have its interface fixed yet
 *
 * This will later be refactored into an Interface of all Ghidra functionality that the RevengService should provide
 * which can then be implemented based on different versions of the Web API
 *
 */
public class GhidraRevengService {
    private BiMap<Function, FunctionID> functionMap = HashBiMap.create();
    private BiMap<Program, BinaryID> programMap = HashBiMap.create();

    private Map<BinaryID, List<GhidraFunctionMatch>> functionMatchCache = new HashMap<>();
    private Map<BinaryID, AnalysisStatus> statusCache = new HashMap<>();

    private TypedApiInterface api;

    public GhidraRevengService(String baseUrl, String apiKey) {
        this.api = new TypedApiImplementation(baseUrl, apiKey);
    }

    public GhidraRevengService(ApiInfo apiInfo){
        this.api = new TypedApiImplementation(apiInfo);
    }

    public GhidraRevengService(){
        this.api = new MockApi();
    }

    public void addBinaryIDforProgram(Program program, BinaryID binID){
        // TODO: Handle the case where the program already has _different_ binary ID
        if (programMap.containsKey(program) && !programMap.get(program).equals(binID)){
            throw new RuntimeException("Program already has different binary ID associated with it: %s".formatted(programMap.get(program)));
        }
        programMap.put(program, binID);
        loadFunctionInfo(program);
        var transactionId = program.startTransaction("Associate Binary ID with Program");
        program.getOptions("Preferences")
                .setLong(ReaiPluginPackage.OPTION_KEY_BINID, binID.value());
        program.endTransaction(transactionId, true);

    }

    /**
     * Tries to find a BinaryID for a given program
     * If the program already has a BinaryID associated with it, it will return that
     * If the program has no BinaryID associated with it and the API doesn't know it, it will return empty
     *
     * @param program
     * @return
     */
    private Optional<BinaryID> getBinaryIDFor(Program program){
        if (programMap.containsKey(program)){
            return Optional.of(programMap.get(program));
        }

        long bid = program.getOptions(
                "Preferences").getLong(ReaiPluginPackage.OPTION_KEY_BINID,
                ReaiPluginPackage.INVALID_BINARY_ID);
        if (bid != ReaiPluginPackage.INVALID_BINARY_ID){
            var binID = new BinaryID((int) bid);
            addBinaryIDforProgram(program, binID);
            return Optional.of(binID);
        }
        return Optional.empty();
    }

    public List<FunctionInfo> getFunctionInfo(Program program){
        var binID = getBinaryIDFor(program);
        if (binID.isEmpty()){
            throw new RuntimeException("No binary ID found for program");
        }
        return api.getFunctionInfo(binID.get());
    }

    private void loadFunctionInfo(Program program){
        var binID = getBinaryIDFor(program);
        if (binID.isEmpty()){
            throw new RuntimeException("No binary ID found for program");
        }
        List<FunctionInfo> functionInfo = api.getFunctionInfo(binID.get());
        var transactionID = program.startTransaction("Load Function Info");
        functionInfo.forEach(
                info -> {
                    var oFunc = getFunctionFor(info, program);
                    if (oFunc.isEmpty()){
                        Msg.error(this, "Function not found for info: %s".formatted(info));
                        return;
                    }
                    var func = oFunc.get();
                    var funcSize = func.getBody().getNumAddresses();
                    // For unclear reasons the func size is off by one
                    if (funcSize - 1 != info.functionSize()){
                        Msg.warn(this, "Function size mismatch for function %s: %d vs %d".formatted(func.getName(), funcSize, info.functionSize()));
                    }
                    if (func.getSymbol().getSource() == SourceType.DEFAULT && !info.functionName().startsWith("FUN_") ){
                        Msg.info(this, "Renaming function %s to %s".formatted(func.getName(), info.functionName()));
                        try {
                            func.setName(info.functionName(), SourceType.ANALYSIS);
                        } catch (DuplicateNameException e) {
                            throw new RuntimeException(e);
                        } catch (InvalidInputException e) {
                            throw new RuntimeException(e);
                        }

                    }

                    functionMap.put(func, info.functionID());
                }
        );
        program.getFunctionManager().getFunctions(true).forEach(
                func -> {
                    if (!func.isExternal() && !func.isThunk() && !functionMap.containsKey(func)){
                        Msg.info(this, "Function %s not found in function info".formatted(func.getName()));
                    }
                }
        );
        program.endTransaction(transactionID, true);
    }

    private Optional<Function> getFunctionFor(FunctionInfo functionInfo, Program program){
        var funcAddress = program.getImageBase().add(functionInfo.functionVirtualAddress());
        return Optional.ofNullable(program.getFunctionManager().getFunctionAt(funcAddress));
    }

    private FunctionID getFunctionIDFor(Function function){
        if (!programMap.containsKey(function.getProgram()))
            throw new RuntimeException("Program not known to the service yet, this method shouldn't have been called");
        if (!functionMap.containsKey(function)){
            loadFunctionInfo(function.getProgram());
//
//            var program = function.getProgram();
//            var functionInfo = getFunctionInfo(program);
//            functionInfo.forEach(
//                    info -> {
//                        functionMap.put(getFunctionFor(info, program), info.functionID());
//
//                    }
//            );
        }
        return functionMap.get(function);
    }
    private List<AnalysisResult> searchForHash(BinaryHash hash){
        return api.search(hash);
    }
    public List<AnalysisResult> searchForProgram(Program program) {
        return searchForHash(hashOfProgram(program));
    }

    public boolean isKnownProgram(Program program){
        return programMap.containsKey(program);
    }

    public boolean isProgramAnalysed(Program program){
        return status(program) == AnalysisStatus.Complete;
    }

    public boolean isKnownFunction(Function function){
        return functionMap.containsKey(function);
    }

    public List<GhidraFunctionMatch> getSimilarFunctions(List<Function> functions, int results, double distance){
        List<FunctionID> functionIDs = functions.stream().map(this::getFunctionIDFor).toList();
        List<FunctionMatch> matches = api.annSymbolsForFunctions(functionIDs, results, distance);

        return matches.stream().map(
                match -> new GhidraFunctionMatch(
                        functionMap.inverse().get(match.origin_function_id()),
                        match
                )
        ).toList();
    }
    public List<GhidraFunctionMatch> getSimilarFunctions(Function function, Double distance, int results) {
        return getSimilarFunctions(List.of(function), results, distance);
    }

    public Map<Function, List<GhidraFunctionMatch>> getSimilarFunctions(Program program, int results, double distance){
        BinaryID binID = getBinaryIDFor(program).orElseThrow();
        var r = api.annSymbolsForBinary(binID, results, distance)
                .stream()
                .map(
                        match -> new GhidraFunctionMatch( functionMap.inverse().get(match.origin_function_id()), match)
                ).collect(
                        Collectors.groupingBy(GhidraFunctionMatch::function)
                );
        return r;

    }



    /**
     * Gets the corresponding FunctionID inside the RevEng Service for a Ghidra Function
     * and then queries for similar functions to this FunctionID
     * @param function
     * @return
     */
    public List<GhidraFunctionMatch> getSimilarFunctions(Function function) {
        return getSimilarFunctions(function, 0.1, 5);
    }

    public List<Collection> collections() {
        return api.collectionQuickSearch(new ModelName("binnet-0.3-x86-linux"));
    }

    public BinaryID analyse(Program program) {
        return analyse(program,
                getModelNameForProgram(program).orElseThrow()
        );
    }

    public BinaryID analyse(Program program, ModelName modelName){
        if (programMap.containsKey(program)){
            return programMap.get(program);
        }

        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder();
        builder.hash(hashOfProgram(program))
                .functionBoundaries(program.getImageBase().getOffset(), exportFunctionBoundaries(program))
                .modelName(modelName)
                .fileName(program.getName());

        var binID = api.analyse(builder);
        programMap.put(program, binID);
        return binID;
    }

    private Optional<ModelName> getModelNameForProgram(Program program){
        // TODO: Model name choice will be removed from the client API in the future
        var format = program.getOptions("Program Information").getString("Executable Format", null);
        if (format.equals(ElfLoader.ELF_NAME)){
            return Optional.of(new ModelName("binnet-0.3-x86-linux"));
        } else if (format.equals(PeLoader.PE_NAME)) {
            return Optional.of(new ModelName("binnet-0.3-x86-windows"));
        }
        return Optional.empty();

    }

    private List<FunctionBoundary> exportFunctionBoundaries(Program program){
        List<FunctionBoundary> result = new ArrayList<>();
        Address imageBase = program.getImageBase();
        program.getFunctionManager().getFunctions(true).forEach(
                function -> {
                    var start = function.getEntryPoint();
                    var end = function.getBody().getMaxAddress();
                    result.add(new FunctionBoundary(function.getName(), start.getOffset(), end.getOffset()));
                }
        );
        return result;
    }

    private BinaryHash hashOfProgram(Program program) {
        // TODO: we break the guarantee that a BinaryHash implies that a file of this hash has already been uploaded
        return new BinaryHash(program.getExecutableSHA256());
    }

    public BinaryHash upload(Program program) {
        // TODO: Check that the file at the path is actually the same as the program (via hash)

        try {
            return api.upload(Path.of(program.getExecutablePath()));
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public BinaryHash upload(Path path) {
        try {
            return api.upload(path);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public AnalysisStatus status(Program program) {
        var bid = getBinaryIDFor(program);
        return status(bid.orElseThrow());
    }

    public AnalysisStatus status(BinaryID bid) {
        if (statusCache.containsKey(bid)){
            return statusCache.get(bid);
        }
        var status = api.status(bid);
        if (status == AnalysisStatus.Complete){
            // The analysis is complete, but it's the first time we get this info
            // so we should load the function info
            loadFunctionInfo(programMap.inverse().get(bid));
            statusCache.put(bid, status);
        }
        return status;
    }

    public String health(){
        return api.healthMessage();
    }


}
