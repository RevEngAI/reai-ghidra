package ai.reveng;

import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import ai.reveng.toolkit.ghidra.plugins.AnalysisManagementPlugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import org.junit.Assert;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class PortalAnalysisIntegrationTest extends RevEngMockableHeadedIntegrationTest {

    @Test
    public void testInfoLoading() throws Exception {

        var tool = env.getTool();
        addMockedService(tool, new UnimplementedAPI() {
            @Override
            public List<FunctionInfo> getFunctionInfo(BinaryID binaryID) {
                return List.of(
                        new FunctionInfo(new FunctionID(1), "portal_name", "portal_name_mangled", 0x4000L, 0x100)
                );
            }
        });
        var builder = new ProgramBuilder("mock", ProgramBuilder._8051, this);
        // Add an example function
        var exampleFunc = builder.createEmptyFunction(null, "0x4000", 0x100, Undefined.getUndefinedDataType(8));
        var program = builder.getProgram();

        var defaultTool = env.showTool(program);

        env.addPlugin(AnalysisManagementPlugin.class);

        waitForSwing();
        var id = new ProgramWithBinaryID(program, new BinaryID(1), new AnalysisID(1));
        var service = defaultTool.getService(GhidraRevengService.class);
        service.addBinaryIDtoProgramOptions(program, id.binaryID());

        // Register a listener for the results loaded event, to verify that has been fired later
        AtomicBoolean receivedResultsLoadedEvent = new AtomicBoolean(false);
        defaultTool.addEventListener(RevEngAIAnalysisResultsLoaded.class, e -> {
            receivedResultsLoadedEvent.set(true);
        });

        // Simulate the analysis status change event
        // We have to run this without waiting, otherwise the test case doesn't continue until the dialog is closed
        runSwing(
                () -> defaultTool.firePluginEvent(
                        new RevEngAIAnalysisStatusChangedEvent(
                                "test",
                                id,
                                AnalysisStatus.Complete
                        )
                ), false
        );

        waitForSwing();
        // Check that we received the results loaded event, i.e. other plugins would have been notified
        assertTrue(receivedResultsLoadedEvent.get());
        // Check that the function names have been updated to the one returned by the portal
        assertEquals("portal_name", exampleFunc.getName());

        // Check the function ID has been stored in the program options
        var funcIDMap = service.getFunctionMap(program);

        var storedFunc = funcIDMap.get(new FunctionID(1));

        Assert.assertNotNull(storedFunc);
        assertEquals("portal_name", storedFunc.getName());

        // Check the function mangled name has been stored
        var mangledNamesMap = service.getFunctionMangledNamesMap(program);

        assertTrue(mangledNamesMap.isPresent());
        assertEquals("portal_name_mangled", mangledNamesMap.get().getString(exampleFunc.getEntryPoint()));

        // TODO: What else should happen when the analysis is finished?
    }
}
