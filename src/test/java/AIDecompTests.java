import ai.reveng.toolkit.ghidra.core.services.api.V2Response;
import ai.reveng.toolkit.ghidra.core.services.api.types.AIDecompilationStatus;
import org.junit.Test;

public class AIDecompTests extends AbstractRevEngIntegrationTest {
    @Test
    public void testDecompilation() {
        V2Response mockResponse = getMockResponseFromFile("ai_decomp_example.json");
        var decompStatus = AIDecompilationStatus.fromJSONObject(mockResponse.getJsonData());

    }

    @Test
    public void testFullMapping() {
        V2Response mockResponse = getMockResponseFromFile("ai_decomp_type_field.json");
        var decompStatus = AIDecompilationStatus.fromJSONObject(mockResponse.getJsonData());
        assert decompStatus.functionMappingFull().inverse_function_map().containsKey(
                new AIDecompilationStatus.PlaceholderToken("<DISASM_FUNCTION_0>"));
//        assert new AIDecompilationStatus.PlaceholderToken("<DISASM_FUNCTION_0>")
        System.out.println(decompStatus.functionMappingFull());
    }


    @Test
    public void testDecompilationWithCustomTypeAndField() {
        V2Response mockResponse = getMockResponseFromFile("ai_decomp_type_field.json");
        var decompStatus = AIDecompilationStatus.fromJSONObject(mockResponse.getJsonData());
        var markedUp = decompStatus.getMarkedUpSummary();
        assert !markedUp.contains("<DISASM_FUNCTION_0>");
//        assert !markedUp.contains("<FIELD_VALUE_0>");
        assert !markedUp.contains("<CUSTOM_TYPE_1>");

    }
}
