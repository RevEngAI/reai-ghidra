package ai.reveng.toolkit.ghidra.binarysimilarity.ui.recentanalyses;

import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.LegacyAnalysisResult;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryHash;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.table.GhidraFilterTable;

import javax.swing.*;
import java.util.Comparator;


/**
 * Shows a dialog with a table of {@link LegacyAnalysisResult} for a given {@link BinaryHash},
 * and fires an event when the user picks an analysis
 */
public class RecentAnalysisDialog extends DialogComponentProvider {
    private final RecentAnalysesTableModel recentAnalysesTableModel;
    private final GhidraFilterTable<LegacyAnalysisResult> recentAnalysesTable;
    private final PluginTool tool;
    private final Program program;

    public RecentAnalysisDialog(PluginTool tool, Program program) {
        super("Recent Analyses", true);
        this.tool = tool;
        this.program = program;
        var hash = new BinaryHash(program.getExecutableSHA256());
        recentAnalysesTableModel = new RecentAnalysesTableModel(tool, hash, this.program.getImageBase());
        recentAnalysesTable = new GhidraFilterTable<>(recentAnalysesTableModel);

        JButton pickMostRecentButton = new JButton("Pick most recent");
        pickMostRecentButton.setName("Pick most recent");
        pickMostRecentButton.addActionListener(e -> {
            var mostRecent = recentAnalysesTable.getModel().getModelData().stream().max(
                    Comparator.comparing(LegacyAnalysisResult::creation)
            ).orElseThrow();
            pickAnalysis(mostRecent);
        });
        addButton(pickMostRecentButton);

        JButton pickSelectedButton = new JButton("Pick selected");
        pickSelectedButton.setName("Pick selected");
        pickSelectedButton.addActionListener(e -> {
            var selectedRowObject = recentAnalysesTable.getSelectedRowObject();
            pickAnalysis(selectedRowObject);
        });
        addButton(pickSelectedButton);

        rootPanel.add(recentAnalysesTable);

    }

    private void pickAnalysis(LegacyAnalysisResult result) {
        var service = tool.getService(GhidraRevengService.class);
        var analysisID = service.getApi().getAnalysisIDfromBinaryID(result.binary_id());
        var programWithID = new ProgramWithBinaryID(program, result.binary_id(), analysisID);
        service.registerFinishedAnalysisForProgram(programWithID);
        tool.firePluginEvent(
                new RevEngAIAnalysisStatusChangedEvent(
                        "Recent Analysis Dialog",
                        programWithID,
                        result.status()
                )
        );
        close();
    }
}
