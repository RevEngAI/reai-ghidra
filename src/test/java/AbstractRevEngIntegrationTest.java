import ai.reveng.toolkit.ghidra.core.services.api.V2Response;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import org.json.JSONObject;

import java.io.IOException;

abstract class AbstractRevEngIntegrationTest extends AbstractGhidraHeadedIntegrationTest {
    protected V2Response getMockResponseFromFile(String filename) {
        String json = null;
        try {
            json = new String(getClass().getClassLoader().getResourceAsStream(filename).readAllBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        JSONObject jsonObject = new JSONObject(json);
        return V2Response.fromJSONObject(jsonObject);

    }
}
