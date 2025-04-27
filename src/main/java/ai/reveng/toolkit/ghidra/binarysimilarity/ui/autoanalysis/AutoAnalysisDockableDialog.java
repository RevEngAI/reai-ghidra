package ai.reveng.toolkit.ghidra.binarysimilarity.ui.autoanalysis;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimilarity.cmds.ComputeTypeInfoTask;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import docking.action.builder.ActionBuilder;
import generic.theme.GIcon;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.TaskLauncher;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Map;

import static ai.reveng.toolkit.ghidra.binarysimilarity.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;

/**
 * Provides a GUI for selecting the similarity threshold for auto renaming of functions
 */
public class AutoAnalysisDockableDialog extends ComponentProviderAdapter {
    private final ToggleNamedOnlyAction toggleNamedOnlyAction;
    private final ToggleFetchSignatures toggleFetchSignatures;
    private JTabbedPane tabbedPanel;

    private AutoAnalysisResultsTableModel autoanalysisResultsModel;
    private GhidraFilterTable<GhidraFunctionMatchWithSignature> analysisResultsTable;

    private JButton btnApplyAllFilteredResults;
    private JButton btnApplySelectedResults;

    public AutoAnalysisDockableDialog(PluginTool tool) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Auto Analysis", ReaiPluginPackage.NAME);

        setIcon(ReaiPluginPackage.REVENG_16);
        tabbedPanel = new JTabbedPane(JTabbedPane.TOP);

        JPanel resultsPanel = this.buildResultsPanel();
        tabbedPanel.addTab("Results", null, resultsPanel, null);

        tool.addComponentProvider(this, false);

        toggleNamedOnlyAction = new ToggleNamedOnlyAction();
        tool.addLocalAction(this, toggleNamedOnlyAction);

        toggleFetchSignatures = new ToggleFetchSignatures();
        tool.addLocalAction(this, toggleFetchSignatures);

        var fetchSimilarFunctionsAction = new FetchSimilarFunctionsAction();
        tool.addLocalAction(this, fetchSimilarFunctionsAction);

        new ActionBuilder("Open Matched Function in Portal", getOwner())
                .popupMenuPath("Open Matched Function in Portal")
                .popupMenuIcon(ReaiPluginPackage.REVENG_16)
                .enabledWhen(ac -> analysisResultsTable.getSelectedRowObject() != null)
                .onAction(ac -> {
                    var selectedRowObject = analysisResultsTable.getSelectedRowObject();
                    tool.getService(GhidraRevengService.class)
                            .openFunctionInPortal(selectedRowObject.functionMatch().nearest_neighbor_id());
                })
                .buildAndInstallLocal(this);

        new ActionBuilder("Compute Type Information for Function(s)", getOwner())
                .popupMenuPath("Compute Type Information")
                .popupMenuIcon(ReaiPluginPackage.REVENG_16)
                .enabledWhen(ac -> !analysisResultsTable.getSelectedRowObjects().isEmpty())
                .onAction( ac -> {
                            Map<FunctionID, GhidraFunctionMatchWithSignature> rowMap = autoanalysisResultsModel.getModelData().stream()
                                    .collect(java.util.stream.Collectors.toMap(m -> m.functionMatch().nearest_neighbor_id(), m -> m));
                            var task = new ComputeTypeInfoTask(tool.getService(GhidraRevengService.class),
                                    analysisResultsTable.getSelectedRowObjects().stream().map( m -> m.functionMatch().nearest_neighbor_id()).toList(),
                                    (f, t) -> {
                                        var entry = rowMap.get(f);
                                        entry.setSignature(t.data_types());
                                        autoanalysisResultsModel.updateObject(entry);
                                    } );
                            tool.execute(task);
                        }
                )
                .buildAndInstallLocal(this);
    }
    @Override
    public ActionContext getActionContext(MouseEvent event) {
        ProgramManager programManager = tool.getService(ProgramManager.class);

        Program currentProgram = programManager.getCurrentProgram();
        return new ProgramActionContext(this, currentProgram, getComponent());
    }


    @Override
    public JComponent getComponent() {
        return tabbedPanel;
    }

    private JPanel buildResultsPanel() {
        JPanel resultsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		autoanalysisResultsModel = new AutoAnalysisResultsTableModel(tool);
        resultsPanel.setLayout(new BorderLayout(0, 0));
        analysisResultsTable = new GhidraFilterTable<>(autoanalysisResultsModel);
		resultsPanel.add(analysisResultsTable);

        analysisResultsTable.installNavigation(tool);


		JPanel actionPanel = new JPanel();
		resultsPanel.add(actionPanel, BorderLayout.SOUTH);
		actionPanel.setLayout(new BorderLayout(0, 0));

        btnApplySelectedResults = new JButton("Apply Selected Results");
        btnApplySelectedResults.setEnabled(false);
        btnApplySelectedResults.addActionListener(
                e -> applyAutoRenameResults(autoanalysisResultsModel.getLastSelectedObjects())
        );

        btnApplyAllFilteredResults = new JButton("Apply Filtered Results");
        btnApplyAllFilteredResults.setEnabled(false);
        btnApplyAllFilteredResults.addActionListener(
                e -> applyAutoRenameResults(autoanalysisResultsModel.getModelData())
        );
        actionPanel.add(btnApplySelectedResults, BorderLayout.WEST);
        actionPanel.add(btnApplyAllFilteredResults, BorderLayout.CENTER);

		resultsPanel.add(actionPanel, BorderLayout.SOUTH);
        return resultsPanel;

    }

    public void loadAutoRenameResults() {
        // Prepare the model with the configured values
        autoanalysisResultsModel.enableLoad();
        // TODO: Make configureable again
        autoanalysisResultsModel.setSimilarityThreshold(0.95);

        // Clear data and reload
        autoanalysisResultsModel.clearData();
        autoanalysisResultsModel.reload();

        btnApplyAllFilteredResults.setEnabled(true);
        btnApplySelectedResults.setEnabled(true);

    }

    /**
     * Method that other parts of the plugin can call to trigger the activation of the dockable and fetch result
     * Occasions to call this include:
     *  - After a successful analysis
     *  - After associating a program with a binary
     */
    public void triggerActivation() {
        this.setVisible(true);
        this.loadAutoRenameResults();
    }

    private void applyAutoRenameResults(List<GhidraFunctionMatchWithSignature> matchesToApply) {
        ProgramManager programManager = tool.getService(ProgramManager.class);

        Program currentProgram = programManager.getCurrentProgram();

        int transactionID = currentProgram.startTransaction(
                "RevEng.AI: Rename %s functions from best match".formatted(matchesToApply.size())
        );

        Namespace revengMatchNamespace = null;
        try {
            revengMatchNamespace = currentProgram.getSymbolTable().getOrCreateNameSpace(
                    currentProgram.getGlobalNamespace(),
                    REVENG_AI_NAMESPACE,
                    SourceType.ANALYSIS
            );
        } catch (DuplicateNameException | InvalidInputException e) {
            throw new RuntimeException(e);
        }

        Namespace finalRevengMatchNamespace = revengMatchNamespace;

        matchesToApply.forEach(
                row -> applyMatch(currentProgram, row, finalRevengMatchNamespace)
        );

        currentProgram.endTransaction(transactionID, true);
        autoanalysisResultsModel.refresh();
    }

    private void applyMatch(Program program, GhidraFunctionMatchWithSignature row, Namespace revengMatchNamespace) {
        try {
            var func = row.function();
            var libraryNamespace = program.getSymbolTable().getOrCreateNameSpace(
                    revengMatchNamespace,
                    row.functionMatch().nearest_neighbor_binary_name(),
                    SourceType.USER_DEFINED);


            func.setParentNamespace(libraryNamespace);

            if (row.signature().isPresent()) {
				var signature = GhidraRevengService.getFunctionSignature(row.signature().get());
                var cmd = new ApplyFunctionSignatureCmd(func.getEntryPoint(), signature, SourceType.USER_DEFINED);
                cmd.applyTo(program);
			} else {
                func.setName(row.functionMatch().nearest_neighbor_function_name(), SourceType.USER_DEFINED);
            }


        } catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
            Msg.showError(this, null,
                    ReaiPluginPackage.WINDOW_PREFIX + "Rename Function Error", e.getMessage(), e);
        }
    }


    private class ToggleNamedOnlyAction extends ToggleDockingAction {

        ToggleNamedOnlyAction() {
            super("Only Show Named", ReaiPluginPackage.NAME);
            setToolBarData(new ToolBarData(new GIcon("icon.plugin.overview.provider")));

        }

        public void actionPerformed(ActionContext context) {
//			getToolBarData().setIcon(enabled ? HOVER_ON_ICON : HOVER_OFF_ICON);
            autoanalysisResultsModel.setOnlyShowNamed(isSelected());
        }
    }

    private class ToggleFetchSignatures extends ToggleDockingAction {

        GIcon SIGNATURES_ON_ICON = new GIcon("icon.plugin.datatypes.archive.project.open");
        GIcon SIGNATURES_OFF_ICON = new GIcon("icon.plugin.datatypes.archive.project.closed");

        ToggleFetchSignatures() {
            super("Include Signatures On Fetch", ReaiPluginPackage.NAME);
            setToolBarData(new ToolBarData(SIGNATURES_OFF_ICON));

        }

        public void actionPerformed(ActionContext context) {
			getToolBarData().setIcon(isSelected() ? SIGNATURES_ON_ICON : SIGNATURES_OFF_ICON);
            autoanalysisResultsModel.setFetchSignatures(isSelected());
        }
    }

    private class FetchSimilarFunctionsAction extends DockingAction {

        public FetchSimilarFunctionsAction() {
            super("Fetch Similar Functions", ReaiPluginPackage.NAME);
            setToolBarData(new ToolBarData(new GIcon("icon.refresh")));
        }

        @Override
        public void actionPerformed(ActionContext context) {
            TaskLauncher.launchModal("Fetch Similar Functions", () -> {
                try {
					loadAutoRenameResults();
                    // Enable buttons


                } catch (Exception exc) {
						Msg.showError(this, analysisResultsTable,
								ReaiPluginPackage.WINDOW_PREFIX + "Auto Analysis Error", exc.getMessage(), exc);
                }
            });
        }
    }
}
