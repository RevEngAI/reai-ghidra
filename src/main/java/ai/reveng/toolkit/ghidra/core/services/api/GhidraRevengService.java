package ai.reveng.toolkit.ghidra.core.services.api;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler.AIDecompiledWindow;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.MockApi;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import ai.reveng.toolkit.ghidra.core.services.api.types.binsync.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIAuthenticationException;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NoValueException;
import ghidra.util.task.TaskMonitor;

import java.awt.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import static ai.reveng.toolkit.ghidra.core.CorePlugin.REAI_OPTIONS_CATEGORY;


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
    private static final String REAI_FUNCTION_PROP_MAP = "RevEngAI_FunctionID_Map";
    private Map<BinaryID, AnalysisStatus> statusCache = new HashMap<>();

    private TypedApiInterface api;
    private ApiInfo apiInfo;

    public TypedApiInterface getApi() {
        return api;
    }

    public GhidraRevengService(ApiInfo apiInfo){
        this.apiInfo = apiInfo;
        this.api = new TypedApiImplementation(apiInfo);
    }

    public GhidraRevengService(TypedApiInterface mockApi){
        this.api = mockApi;
        this.apiInfo = new ApiInfo("http://localhost:8080", "mock");
    }

    public GhidraRevengService(){
        this.api = new MockApi();
    }

    public URI getServer() {
        return this.apiInfo.hostURI();
    }

    public void handleAnalysisCompletion(RevEngAIAnalysisStatusChangedEvent event){
        if (event.getStatus() != AnalysisStatus.Complete){
            throw new RuntimeException("Method should only be called when analysis is complete");
        }
        statusCache.put(event.getProgramWithBinaryID().binaryID(), AnalysisStatus.Complete);
        Program program = event.getProgram();
        BinaryID binID = event.getBinaryID();

        loadFunctionInfo(program, binID);
        addBinaryIDtoProgramOptions(program, binID);
    }

    public void addBinaryIDtoProgramOptions(Program program, BinaryID binID){
        var transactionId = program.startTransaction("Associate Binary ID with Program");
        program.getOptions(REAI_OPTIONS_CATEGORY)
                .setLong(ReaiPluginPackage.OPTION_KEY_BINID, binID.value());
        program.endTransaction(transactionId, true);
    }

    /**
     * Tries to find a BinaryID for a given program
     * If the program already has a BinaryID associated with it, it will return that
     * If we don't have a BinaryID it will return an empty Optional
     * @param program
     * @return
     */
    public Optional<BinaryID> getBinaryIDFor(Program program) {
        Optional<BinaryID> binID;
        try {
            binID = getBinaryIDfromOptions(program);
        } catch (InvalidBinaryID e) {
            Msg.error(this, "Invalid Binary ID found in program options: %s".formatted(e.getMessage()));
            return Optional.empty();
        }
        return binID;

    }

    public Optional<AnalysisID> getAnalysisIDFor(Program program){
        return getBinaryIDFor(program).map(binID -> api.getAnalysisIDfromBinaryID(binID));
    }


    public Optional<BinaryID> getBinaryIDfromOptions(
            Program program
    ) throws InvalidBinaryID {
        long bid = program.getOptions(
                REAI_OPTIONS_CATEGORY).getLong(ReaiPluginPackage.OPTION_KEY_BINID,
                ReaiPluginPackage.INVALID_BINARY_ID);
        if (bid == ReaiPluginPackage.INVALID_BINARY_ID) {
            return Optional.empty();
        }
        var binID = new BinaryID((int) bid);
        if (!statusCache.containsKey(binID)) {
            // Check that it's really valid in the context of the currently configured API
            try {
                var status = api.status(binID);
                statusCache.put(binID, status);
            } catch (APIAuthenticationException e) {
                throw new InvalidBinaryID(binID, this.apiInfo);
            }
            // Now it's certain that it is a valid binary ID
        }
        return Optional.of(binID);


    }

    public List<GhidraFunctionInfo> getFunctionInfo(Program program){
        var binID = getBinaryIDFor(program);
        if (binID.isEmpty()){
            throw new RuntimeException("No binary ID found for program");
        }
        return api.getFunctionInfo(binID.get()).stream()
                .map(
                        info -> new GhidraFunctionInfo(
                                info,
                                getFunctionFor(info, program).orElse(null)
                        ))
                // Work around the incorrect function vaddr bug
                .filter(ghidraFunctionInfo -> ghidraFunctionInfo.function() != null)
                .toList();
    }

    private void loadFunctionInfo(Program program, BinaryID binID){
        List<FunctionInfo> functionInfo = api.getFunctionInfo(binID);
        var transactionID = program.startTransaction("Load Function Info");

        // Create the FunctionID map
        LongPropertyMap functionIDMap;
        try {
            functionIDMap = program.getUsrPropertyManager().createLongPropertyMap(REAI_FUNCTION_PROP_MAP);
        } catch (DuplicateNameException e) {
            program.endTransaction(transactionID, false);
            throw new RuntimeException("Previous function property map still exists",e);
        }

        LongPropertyMap finalFunctionIDMap = functionIDMap;
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
                    finalFunctionIDMap.add(func.getEntryPoint(), info.functionID().value());
                }
        );
        program.getFunctionManager().getFunctions(true).forEach(
                func -> {
                    if (!func.isExternal() && !func.isThunk() && getFunctionIDFor(func).isEmpty()){
                        Msg.info(this, "Function %s not found in function info".formatted(func.getName()));
                    }
                }
        );
        program.endTransaction(transactionID, true);
    }

    /**
     * Get the FunctionID for a Ghidra Function, if there is one
     *
     * There are two cases where a function ID is missing:
     * 1. Either the whole program has not been analyzed
     * 2. Or the function was not found as part of the analysis on the server
     * (because its bounds were not included when the analysis was triggered)
     */
    public Optional<FunctionID> getFunctionIDFor(Function function){
        return getKnownProgram(function.getProgram())
                .flatMap(knownProgram -> getFunctionIDFor(knownProgram, function));
    }

    public Optional<FunctionID> getFunctionIDFor(ProgramWithBinaryID knownProgram, Function function){
        Optional<LongPropertyMap> functionIDMap = getFunctionIDMap(knownProgram);

        return functionIDMap
                .flatMap(map -> Optional.ofNullable(map.get(function.getEntryPoint())))
                .map(FunctionID::new);
    }

    private Optional<LongPropertyMap> getFunctionIDMap(ProgramWithBinaryID program){
        return Optional.ofNullable(program.program().getUsrPropertyManager().getLongPropertyMap(REAI_FUNCTION_PROP_MAP));
    }

    public BiMap<FunctionID, Function> getFunctionMap(Program program){
        var propMap = program.getUsrPropertyManager().getLongPropertyMap(REAI_FUNCTION_PROP_MAP);
        BiMap<FunctionID, Function> functionMap = HashBiMap.create();
        propMap.getPropertyIterator().forEachRemaining(
                addr -> {
                    var func = program.getFunctionManager().getFunctionAt(addr);

                    try {
                        functionMap.put(new FunctionID(propMap.getLong(addr)), func);
                    } catch (NoValueException e) {
                        // This should never happen, because we're iterating over the keys
                        throw new RuntimeException(e);
                    }
                }
        );
        return functionMap;
    }

    public Optional<Function> getFunctionFor(FunctionInfo functionInfo, Program program){
        var funcAddress = program.getImageBase().add(functionInfo.functionVirtualAddress());
        var func = program.getFunctionManager().getFunctionAt(funcAddress);
        return Optional.ofNullable(func);
    }

    public List<AnalysisResult> searchForHash(BinaryHash hash){
        return api.search(hash);
    }
    public List<AnalysisResult> searchForProgram(Program program) {
        return searchForHash(hashOfProgram(program));
    }

    public boolean isKnownProgram(Program program){
        var storedBinID = program.getOptions(REAI_OPTIONS_CATEGORY).getLong(ReaiPluginPackage.OPTION_KEY_BINID, ReaiPluginPackage.INVALID_BINARY_ID);
        return storedBinID != ReaiPluginPackage.INVALID_BINARY_ID;
    }

    public void removeProgramAssociation(Program program){
        var binID = getBinaryIDFor(program);
        if (binID.isEmpty()){
            throw new RuntimeException("Program has no binary ID associated with it");
        }
        // Clear all function ID data
        program.getUsrPropertyManager().removePropertyMap(REAI_FUNCTION_PROP_MAP);
        statusCache.remove(binID.get());
        program.getOptions(REAI_OPTIONS_CATEGORY).setLong(ReaiPluginPackage.OPTION_KEY_BINID, ReaiPluginPackage.INVALID_BINARY_ID);
    }

    public boolean isProgramAnalysed(Program program){
        return program.getUsrPropertyManager().getLongPropertyMap(REAI_FUNCTION_PROP_MAP) != null;
    }

    public boolean isKnownFunction(Function function){
        return getFunctionIDFor(function).isPresent();
    }

    public List<GhidraFunctionMatch> getSimilarFunctions(List<Function> functions, int results, double distance, boolean debugMode){

        // Get the FunctionIDs for all the functions
        List<FunctionID> functionIDs = functions.stream().map(this::getFunctionIDFor).map(Optional::orElseThrow).toList();
        // Look up the matches via the API
        List<FunctionMatch> matches = api.annSymbolsForFunctions(functionIDs, results, distance, debugMode);

        // Prepare the map from FunctionID -> Ghidra Function
        BiMap<FunctionID, Function> functionMap = getFunctionMap(functions.get(0).getProgram());

        // Return the matches as GhidraFunctionMatches
        return matches.stream().map(
                match -> new GhidraFunctionMatch(
                        functionMap.get(match.origin_function_id()),
                        match
                )
        ).toList();
    }

    public List<GhidraFunctionMatch> getSimilarFunctions(Function function, Double distance, int results, boolean debugMode) {
        return getSimilarFunctions(List.of(function), results, distance, debugMode);
    }

    public Map<Function, List<GhidraFunctionMatch>> getSimilarFunctions(
            Program program,
            int results,
            double distance,
            boolean debugMode,
            List<Collection> collections
    ){
        BinaryID binID = getBinaryIDFor(program).orElseThrow();
        var functionMap = getFunctionMap(program);
        var r = api.annSymbolsForBinary(binID, results, distance, debugMode, collections)
                .stream()
                .map(
                        // Augment each match returned by the API with the associated Ghidra Function
                        match -> new GhidraFunctionMatch( functionMap.get(match.origin_function_id()), match)
                )
                .filter(
                        // Filter out matches where the function is null due to some bug
                        ghidraFunctionMatch -> ghidraFunctionMatch.function() != null
                ).collect(
                        // Group the matches by the Ghidra Function, so we have the matches per local function
                        Collectors.groupingBy(GhidraFunctionMatch::function)
                );
        return r;

    }

    public Map<Function, List<GhidraFunctionMatch>> getSimilarFunctions(Program program, int results, Double distance, Boolean debugMode) {
        return getSimilarFunctions(program, results, distance, debugMode, List.of());
    }



    /**
     * Gets the corresponding FunctionID inside the RevEng Service for a Ghidra Function
     * and then queries for similar functions to this FunctionID
     * @param function
     * @return
     */
    public List<GhidraFunctionMatch> getSimilarFunctions(Function function) {
        // TODO: This could maybe be made configureable
        // Problem is that the API should also work without a tool, so we can't rely on the tool options being available
        return getSimilarFunctions(function, 0.1, 5, false);
    }

    public List<Collection> collections() {
        return api.collectionQuickSearch(new ModelName("binnet-0.3-x86-linux"));
    }

    public ProgramWithBinaryID analyse(Program program) {
        return analyse(program, getModelNameForProgram(program));
    }

    public ProgramWithBinaryID analyse(Program program, ModelName modelName){
        if (isKnownProgram(program)){
            return new ProgramWithBinaryID(program, getBinaryIDFor(program).orElseThrow());
        }

        AnalysisOptionsBuilder builder = new AnalysisOptionsBuilder();
        builder.hash(hashOfProgram(program))
                .functionBoundaries(program.getImageBase().getOffset(), exportFunctionBoundaries(program))
                .modelName(modelName)
                .fileName(program.getName());

        var binID = api.analyse(builder);
        statusCache.put(binID, AnalysisStatus.Queued);
        return new ProgramWithBinaryID(program, binID);
    }

    private ModelName getModelNameForProgram(Program program){
        return getModelNameForProgram(program, this.api.models());
    }

    public ModelName getModelNameForProgram(Program program, List<ModelName> models){
        var s = models.stream().map (ModelName::modelName);
        var format = program.getOptions("Program Information").getString("Executable Format", null);
        if (format.equals(ElfLoader.ELF_NAME)){
            s = s.filter(modelName -> modelName.contains("linux"));
        } else if (format.equals(PeLoader.PE_NAME)) {
            s = s.filter(modelName -> modelName.contains("windows"));
        }
        return new ModelName(s.sorted(Collections.reverseOrder()).toList().get(0));
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
        // TODO: Check if the program is already uploaded on the server
        // But this requires a dedicated API to do cleanly

        Path filePath;
        try {
            filePath = Path.of(program.getExecutablePath());
        } catch (InvalidPathException e) {
            // For windows the returned String isn't a valid input to Path.of
            //  because they look like "/C:/vfcompat.dll"
            // we have to drop the first "/" for the path to be valid
            filePath = Path.of(program.getExecutablePath().substring(1));
        }
        try {
            var hash = api.upload(filePath);
            if (hash.equals(hashOfProgram(program))){
                // TODO: Save the information that this program has been uploaded
//                program.getOptions(REAI_OPTIONS_CATEGORY).setBoolean(ReaiPluginPackage.OPTION_KEY_BINID, hash.value());
                return hash;
            } else {
                // This means the file on disk has
                throw new RuntimeException(
                        "Hash of uploaded file %s from path %s doesn't match the hash of the program loaded in Ghidra %s"
                                .formatted(hash, program.getExecutablePath(), hashOfProgram(program)));
            }
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

    public AnalysisStatus pollStatus(Program program) {
        var bid = getBinaryIDFor(program);
        return pollStatus(bid.orElseThrow());
    }

    public AnalysisStatus pollStatus(BinaryID bid) {
        var status = api.status(bid);
        return status;
    }

    public String health(){
        return api.healthMessage();
    }

    public List<ModelName> getAvailableModels(){
        return api.models();
    }


    public String decompileFunctionViaAI(Function function, TaskMonitor monitor, AIDecompiledWindow window) {
        monitor.setMaximum(100 * 50);
        var fID = getFunctionIDFor(function)
                .orElseThrow(() -> new RuntimeException("Function has no associated FunctionID"));
        // Check if there is an existing process already, because the trigger API will fail with 400 if there is
        if (api.pollAIDecompileStatus(fID).status().equals("uninitialised")){
            // Trigger the decompilation
            api.triggerAIDecompilationForFunctionID(fID);
        }


        while (true) {
            if (monitor.isCancelled()) {
                return "Decompilation cancelled";
            }
            var status = api.pollAIDecompileStatus(fID);
            window.setStatus(status.status());

            switch (status.status()) {
                case "pending":
                case "uninitialised":
                case "queued":
                case "running":
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
//                    monitor.incrementProgress(100);
                    break;
                case "success":
                    monitor.setProgress(monitor.getMaximum());
                    window.setCode(status.decompilation());
                    return status.decompilation();
                case "error":
                    return "Decompilation failed: %s".formatted(status.decompilation());
                default:
                    throw new RuntimeException("Unknown status: %s".formatted(status.status()));
            }



        }
    }

    public Optional<ProgramWithBinaryID> getKnownProgram(Program program) {
        return getBinaryIDFor(program).map(binID -> new ProgramWithBinaryID(program, binID));
    }

    public Optional<FunctionDataTypeMessage> getFunctionSignatureArtifact(BinaryID binID, FunctionID functionID) {
        var analysisID = api.getAnalysisIDfromBinaryID(binID);
        return api.getFunctionDataTypes(analysisID, functionID).flatMap(FunctionDataTypeStatus::data_types);
    }

    /**
     * Create a {@link FunctionDefinitionDataType} from a @{@link FunctionDataTypeMessage} in isolation
     *
     * All the required dependency types should be stored in the DataTypeManager that is associated with this
     * FunctionDefinitionDataType
     *
     * @param functionDataTypeMessage The message containing the function signature, received from the API
     * @return Self-contained signature for the function
     */
    public static FunctionDefinitionDataType getFunctionSignature(FunctionDataTypeMessage functionDataTypeMessage){

        // TODO: Do we need the program or data type manager?
        // Or can we just create a new one with all the necessary types and then they get merged?

        // Create Data Type Manager with all dependencies
        var dtm = loadDependencyDataTypes(functionDataTypeMessage.func_deps());

        FunctionDefinitionDataType f = new FunctionDefinitionDataType(functionDataTypeMessage.functionName(), dtm);

        try {
            f.setName(functionDataTypeMessage.functionName());
        } catch (InvalidNameException e) {
            throw new RuntimeException(e);
        }

        ParameterDefinitionImpl[] args = Arrays.stream(functionDataTypeMessage.func_types().header().args()).map(
                arg -> {
                    DataType ghidraType = null;
                    try {
                        ghidraType = loadDataType(dtm, arg.type(), functionDataTypeMessage.func_deps());
                    } catch (DataTypeDependencyException e) {
                        Msg.error(GhidraRevengService.class,
                                "Couldn't find type '%s' for param of %s".formatted(arg.type(), functionDataTypeMessage.functionName())
                        );
                        ghidraType = Undefined.getUndefinedDataType(arg.size());
                    }
                    // Add the type to the DataTypeManager
                    return new ParameterDefinitionImpl(arg.name(), ghidraType, null);
                }).toArray(ParameterDefinitionImpl[]::new);

        f.setArguments(args);

        DataType returnType = null;
        try {
            returnType = loadDataType(dtm, functionDataTypeMessage.func_types().header().type(), functionDataTypeMessage.func_deps());
        } catch (DataTypeDependencyException e) {
            throw new RuntimeException(e);
        }
        f.setReturnType(returnType);


        return f;
    }

    public static DataTypeManager loadDependencyDataTypes(FunctionDependencies dependencies){
        DataTypeManager dtm = new StandAloneDataTypeManager("transient");

        if (dependencies == null){
            return dtm;
        }
        DataTypeParser dataTypeParser = new DataTypeParser(
                dtm,
                null,
                null,
                DataTypeParser.AllowedDataTypes.ALL);

        // We do this in two passes:

        // First add all types as empty placeholders
        var transactionId = dtm.startTransaction("Load Dependencies");
        Arrays.stream(dependencies.structs()).forEach(
                struct -> {
//                        CategoryPath path = new CategoryPath(CategoryPath.ROOT, struct.name().split("/"));
                        var path = TypePathAndName.fromString(struct.name());

                        StructureDataType structDataType = new StructureDataType(
                                new CategoryPath(CategoryPath.ROOT, path.path()),
                                path.name(),
                                struct.size(),
                                dtm);
                        dtm.addDataType(structDataType, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
                }
        );
        // The following would be a lot nicer of BinSync could guarantee us that all dependencies are sorted
        // As a workaround we just retry until all types are available
        // In some cases (specifically bugs in BinSync when dependencies are missing) this will loop forever by default
        // To work around _that_ we have a limit of 1000 retries
        Queue<Typedef> typeDefsToAdd = Arrays.stream(dependencies.typedefs()).collect(Collectors.toCollection(LinkedList::new));
        int retries = 0;
        while (!typeDefsToAdd.isEmpty()){
            if (retries > 1000){
                throw new RuntimeException("Dependency loading failed: %s".formatted(typeDefsToAdd));
            }
            var typeDef = typeDefsToAdd.remove();
            var path = TypePathAndName.fromString(typeDef.name());
            DataType type;
            try {
                type = dataTypeParser.parse(typeDef.type());
            } catch (InvalidDataTypeException e) {
                // The type wasn't available in the DataTypeManager yet, try again later
                typeDefsToAdd.add(typeDef);
                retries++;
                continue;
            } catch (CancelledException e) {
                throw new RuntimeException(e);
            }
            TypedefDataType typedefDataType = new TypedefDataType(new CategoryPath(CategoryPath.ROOT, path.path()), path.name(), type, null);
            dtm.addDataType(typedefDataType, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
        }

        // Now we have all necessary types, we can fill out the structs
        Arrays.stream(dependencies.structs()).forEach(
                struct -> {
                    var path = TypePathAndName.fromString(struct.name());
                    // Get struct type
                    var type = dtm.getDataType(path.toCategoryPath(), path.name());
                    if (type instanceof Structure structType) {
                        Arrays.stream(struct.members()).forEach(
                                binSyncStructMember -> {
                                    DataType fieldType = null;
                                    try {
                                        fieldType = loadDataType(dtm, binSyncStructMember.type(), dependencies);
                                    } catch (DataTypeDependencyException e) {
                                        Msg.error(
                                                GhidraRevengService.class,
                                                "Couldn't find type '%s' for field of %s".formatted(binSyncStructMember.type(), struct.name())
                                        );
                                        fieldType = Undefined.getUndefinedDataType(binSyncStructMember.size());
                                    }
                                    structType.replaceAtOffset(
                                            binSyncStructMember.offset(),
                                            fieldType,
                                            binSyncStructMember.size(),
                                            binSyncStructMember.name(),
                                            null
                                    );
                                }
                        );
                    } else {
                        throw new RuntimeException("Struct type not found: %s".formatted(struct.name()));
                    }

                }
        );

        dtm.endTransaction(transactionId, true);
        return dtm;
    }

    private static DataType loadDataType(DataTypeManager dtm, String name, FunctionDependencies dependencies) throws DataTypeDependencyException {
        DataTypeParser dataTypeParser = new DataTypeParser(
                dtm,
                null,
                null,
                DataTypeParser.AllowedDataTypes.ALL);
        DataType dataType;
        try {
            dataType = dataTypeParser.parse(name);
        } catch (InvalidDataTypeException e) {
            // The type wasn't available in the DataTypeManager, so we have to find it in the dependencies
            throw new DataTypeDependencyException("Data type not found in DataTypeManager: %s".formatted(name), e);
        } catch (CancelledException e) {
            throw new RuntimeException(e);
        }
        return dataType;
    }

    public Map<FunctionID, String> pushUserFunctionNamesToBackend(Program program) {
        Map<FunctionID, String> renameDict = getFunctionMap(program).entrySet().stream()
                .filter(entry -> entry.getValue().getSymbol().getSource() == SourceType.USER_DEFINED)
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().getName()));
        if (renameDict.isEmpty()){
            return renameDict;
        }
        api.renameFunctions(renameDict);
        return renameDict;
    }

    public String getAnalysisLog(AnalysisID analysisID) {
        return api.getAnalysisLogs(analysisID);
    }

    /**
     * Get the "name score" confidence of a match via the new API.
     * The old kind of confidence is now called similarity
     *
     * @param functionMatch the match to get the confidence for
     * @return the confidence of the match
     */
    public BoxPlot getNameScoreForMatch(GhidraFunctionMatch functionMatch) {
        var functionNameScore = api.getNameScore(functionMatch.functionMatch());
        return functionNameScore.score();

    }

    public static final String PORTAL_FUNCTIONS = "function/";

    public void openFunctionInPortal(FunctionID functionID) {
        openPortal(PORTAL_FUNCTIONS, String.valueOf(functionID.value()));
    }

    public void openPortal(String... subPath) {
        // For now this is hardcoded, but it should be configurable later
        // Potentially this will be provided by an endpoint in the API
        StringBuilder sb = new StringBuilder("https://portal.reveng.ai/");
        for (String s : subPath) {
            sb.append(s);
            sb.append("/");
        }
        openURI(URI.create(sb.toString()));
    }

    private void openURI(URI uri){
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)
        ) {
            try {
                Desktop.getDesktop().browse(uri);
            } catch (IOException e) {
                Msg.showError(
                        this,
                        null,
                        "URI Opening Failed",
                        "Browsing to URI %s failed".formatted(uri),
                        e
                );
            }
        } else {
            Msg.showError(
                    this,
                    null,
                    "URI Opening unsupported",
                    "URI %s couldn't be opened because the environment doesn't support opening URLs".formatted(uri)
            );

        }
    }

}
