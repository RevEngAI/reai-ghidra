package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ghidra.test.TestEnv;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class TestMockableService extends RevEngMockableHeadedIntegrationTest {

    /// Basic test and demo for mocking the API
    @Test
    public void test() {
        List<ModelName> models = List.of(new ModelName("demo-model"));
        var addedService = addMockedService(env.getTool(), new UnimplementedAPI() {
            @Override
            public List<ModelName> models() {
                return models;
            }
        });

        var returnedService = env.getTool().getService(GhidraRevengService.class);
        assertNotNull(returnedService);
        assertEquals(addedService, returnedService);
        assertEquals(models, returnedService.getAvailableModels());


    }
}
