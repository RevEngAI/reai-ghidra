package ai.reveng;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.autoanalysis.AutoAnalysisComponentProvider;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.autoanalysis.AutoAnalysisResultsTableModel;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded;
import ai.reveng.toolkit.ghidra.core.services.api.mocks.UnimplementedAPI;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.Undefined;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import javax.swing.*;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AutoAnalysisComponentTest  extends RevEngMockableHeadedIntegrationTest{


    @Test
    public void testAutoAnalysisComponent() throws Exception {
// Check that the Auto Analyse Window is visible and has content
        var tool = env.getTool();

        var service = addMockedService(tool, new UnimplementedAPI() {
            @Override
            public AnalysisStatus status(AnalysisID analysisID) {
                return AnalysisStatus.Complete;
            }

            @Override
            public List<FunctionInfo> getFunctionInfo(BinaryID binaryID) {
                return List.of(
                        new FunctionInfo(
                                new FunctionID(1),
                                "default_function_info_name",
                                0x1000L,
                                10)
                );
            }

            @Override
            public List<FunctionMatch> annSymbolsForBinary(BinaryID binID, int resultsPerFunction, double distance, boolean debugMode, List<Collection> collections) {
                return List.of(
                        new FunctionMatch(
                                new FunctionID(1),
                                new FunctionID(2),
                                "matched_function_name",
                                "matched_binary",
                                new BinaryHash("matched_binary_hash"),
                                new BinaryID(2),
                                true,
                                1
                        )
                );
            }
        });

        var binarySimilarityPlugin = env.addPlugin(BinarySimilarityPlugin.class);

        var builder = new ProgramBuilder("mock", ProgramBuilder._8051, this);
        var func = builder.createEmptyFunction(null, "0x1000", 10, Undefined.getUndefinedDataType(4));
        var programWithID = service.analyse(builder.getProgram(), null, TaskMonitor.DUMMY);

        env.showTool(programWithID.program());
        // Everything is prepared, as if the analysis had been run and completed
        // Now the "user" triggers the "Function Matching" UI action
        var action = getAction(tool, "Function Matching");
        performAction(action, false);


        AutoAnalysisComponentProvider autoAnalysisProvider = (AutoAnalysisComponentProvider) getInstanceField("autoAnalyse", binarySimilarityPlugin);
        assertTrue(autoAnalysisProvider.getComponent().isVisible());

        AutoAnalysisResultsTableModel tableModel = (AutoAnalysisResultsTableModel) getInstanceField("autoanalysisResultsModel", autoAnalysisProvider);
        waitForTableModel(tableModel);

        assertEquals(1, tableModel.getRowCount());

        // Get the button to apply the matches named "Apply Filtered Results"
        JButton applyButton = (JButton) getInstanceField("btnApplyAllFilteredResults", autoAnalysisProvider);
        applyButton.doClick();
        waitForSwing();

        // Our local function should now be:
        // Renamed to "matched_function_name"
        // In the "RevEng.AI" namespace
        // In a sub-namespace named after the matched binary, i.e. "matched_binary"
        // TODO: Check that the type signature info was applied?
        assertEquals("matched_function_name", func.getName());
        assertEquals(BinarySimilarityPlugin.REVENG_AI_NAMESPACE, func.getParentNamespace().getParentNamespace().getName(false));
        assertEquals("matched_binary", func.getParentNamespace().getName(false));


        // Apply the matches via the UI button
    }
}
