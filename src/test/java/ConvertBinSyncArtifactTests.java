import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.V2Response;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionDataTypeStatus;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;
import org.json.JSONObject;
import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ConvertBinSyncArtifactTests extends AbstractGhidraHeadlessIntegrationTest {

    private V2Response getMockResponseFromFile(String filename) {
        String json = null;
        try {
            json = new String(getClass().getClassLoader().getResourceAsStream(filename).readAllBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        JSONObject jsonObject = new JSONObject(json);
        return V2Response.fromJSONObject(jsonObject);

    }

    @Test
    public void testSimpleGhidraSignatureGeneration() {
        V2Response mockResponse = getMockResponseFromFile("main_fdupes_77846709.json");

        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var signature = GhidraRevengService.getFunctionSignature(functionDataTypeStatus.data_types().get());

        assert signature.getName().equals("main");
        assert signature.getReturnType().getName().equals("int");
        assert signature.getArguments().length == 2;

        assert signature.getArguments()[0].getName().equals("argc");
        assert signature.getArguments()[0].getDataType().getName().equals("int");

        assert signature.getArguments()[1].getName().equals("argv");
        assert signature.getArguments()[1].getDataType().getName().equals("char * *");
    }




    @Test
    public void testDependencyToDtm() {
        var mockResponse = getMockResponseFromFile("confirmmatch_fdupes_77846700.json");
        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var dtm = GhidraRevengService.loadDependencyDataTypes(functionDataTypeStatus.data_types().get().func_deps());


        // Print all datatypes for debugging
        for (Iterator<DataType> it = dtm.getAllDataTypes(); it.hasNext(); ) {
            var ty = it.next();
            Msg.info(this, ty.getCategoryPath());
            Msg.info(this, ty.getName());
        }
        // There should be a typedef FILE in the folder DWARF/stdio.h/ for
        var fileType = dtm.getDataType(new  CategoryPath(CategoryPath.ROOT, "DWARF", "stdio.h"), "FILE");
        List<DataType> results = new ArrayList();
        dtm.findDataTypes("FILE", results);
        assert fileType != null;

    }

    @Test
    public void testComplexGhidraSignatureGeneration() {
        var mockResponse = getMockResponseFromFile("confirmmatch_fdupes_77846700.json");

        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var signature = GhidraRevengService.getFunctionSignature(functionDataTypeStatus.data_types().get());

        assert signature.getName().equals("confirmmatch");
        Msg.info(this, signature);
    }


    @Test
    public void testComplexGhidraSignatureGeneration2() {
        var mockResponse = getMockResponseFromFile("summarizematches_fdupes.json");

        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var signature = GhidraRevengService.getFunctionSignature(functionDataTypeStatus.data_types().get());

        assert signature.getName().equals("summarizematches");
        Msg.info(this, signature);
    }

    @Test
    public void testComplexGhidraSignatureGeneration3() {
        var mockResponse = getMockResponseFromFile("md5_process_fdupes.json");

        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var signature = GhidraRevengService.getFunctionSignature(functionDataTypeStatus.data_types().get());

        var dtm = signature.getDataTypeManager();
        assert signature.getName().equals("md5_process");

        Structure stateType = (Structure) dtm.getDataType("/DWARF/md5.h/md5_state_s");
        assert stateType.getLength() == 88;
        assert stateType.getNumComponents() == 3;

    }


    /**
     * This test is to ensure that the function signature generation does not loop infinitely
     */
    @Test
    public void testNoLoopForBrokenDeps() {
        var mockResponse = getMockResponseFromFile("errormsg.json");

        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var signature = GhidraRevengService.getFunctionSignature(functionDataTypeStatus.data_types().get());

        assert signature.getName().equals("md5_process");
        Msg.info(this, signature);
    }

    /**
     * This function takes a function pointer as an argument
     * BinSync doesn't serialize them by default, and this specific example JSON is missing it
     * The function is `registerpair` from `fdupes`: <a href="https://portal.reveng.ai/function/77846706?tab=Disassembly">registerpair</a>
     */
    @Test
    public void testFunctionPointerArgument() {
        var mockResponse = getMockResponseFromFile("complex_pointer.json");
        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        var signature = GhidraRevengService.getFunctionSignature(functionDataTypeStatus.data_types().get());
    }

    @Test
    public void testPendingStatus() {
        var mockResponse = getMockResponseFromFile("pending.json");
        FunctionDataTypeStatus functionDataTypeStatus = FunctionDataTypeStatus.fromJson(mockResponse.getJsonData());
        assert !functionDataTypeStatus.completed();
        assert functionDataTypeStatus.data_types().isEmpty();
        assert functionDataTypeStatus.status().equals("pending");
    }


}
