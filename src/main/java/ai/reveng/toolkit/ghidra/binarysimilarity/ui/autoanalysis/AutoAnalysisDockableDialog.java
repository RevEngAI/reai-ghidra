package ai.reveng.toolkit.ghidra.binarysimilarity.ui.autoanalysis;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingWorker;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.Collection;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.ToolBarData;
import docking.widgets.table.GFilterTable;
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
import java.util.stream.Collectors;

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

    private CollectionTableModel collectionsModel;
    private GFilterTable<CollectionRowObject> collectionsTable;

    private JButton btnApplyAllFilteredResults;
    private JButton btnApplySelectedResults;
    private JButton btnFetchCollections;

    public AutoAnalysisDockableDialog(PluginTool tool) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Auto Analysis", ReaiPluginPackage.NAME);

        setIcon(ReaiPluginPackage.REVENG_16);
        tabbedPanel = new JTabbedPane(JTabbedPane.TOP);

        JPanel resultsPanel = this.buildResultsPanel();
        tabbedPanel.addTab("Results", null, resultsPanel, null);

        JPanel collectionsPanel = this.buildCollectionsPanel();
        tabbedPanel.addTab("Collections", null, collectionsPanel, null);

        tool.addComponentProvider(this, false);

        toggleNamedOnlyAction = new ToggleNamedOnlyAction();
        tool.addLocalAction(this, toggleNamedOnlyAction);

        toggleFetchSignatures = new ToggleFetchSignatures();
        tool.addLocalAction(this, toggleFetchSignatures);

        var fetchSimilarFunctionsAction = new FetchSimilarFunctionsAction();
        tool.addLocalAction(this, fetchSimilarFunctionsAction);

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

    private JPanel buildCollectionsPanel() {
        var collectionsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        collectionsModel = new CollectionTableModel(tool);
        collectionsPanel.setLayout(new BorderLayout(0, 0));
        collectionsTable = new GFilterTable<>(collectionsModel);
        collectionsPanel.add(collectionsTable);

        var collectionSearchTextbox = new JTextField();
        collectionSearchTextbox.setColumns(10);
        btnFetchCollections = new JButton("Load Matching Collections");
        btnFetchCollections.setEnabled(true);
        btnFetchCollections.addActionListener(e -> {
            SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
                @Override
                protected Void doInBackground() throws Exception {
                    var serv = tool.getService(GhidraRevengService.class);
                    // Get all rows that are already selected to be included
                    var selectedCollections = collectionsModel.getModelData().stream()
                            .filter(CollectionRowObject::isInclude)
                            .toList();

                    var selectedSet = selectedCollections.stream()
                            .map(CollectionRowObject::getCollectionName)
                            .collect(Collectors.toSet());
                    collectionsModel.clearData();

                    var searchTerm = collectionSearchTextbox.getText();
                    serv.getApi().collectionQuickSearch(searchTerm).forEach(
                            collection -> {
                                if (!selectedSet.contains(collection.collectionName())) {
                                    collectionsModel.addObject(new CollectionRowObject(collection, false));
                                }
                            }

                    );

                    // Add the previously selected models back
                    selectedCollections.forEach(
                            collection -> collectionsModel.addObject(collection)
                    );

                    return null;
                }
            };
            worker.execute();

        });

        var collectionBtnPnl = new JPanel(new FlowLayout(FlowLayout.CENTER));

        collectionBtnPnl.add(collectionSearchTextbox);
        collectionBtnPnl.add(btnFetchCollections);

        collectionsPanel.add(collectionBtnPnl, BorderLayout.SOUTH);

        return collectionsPanel;
    }

    public void loadAutoRenameResults() {
        // Prepare the model with the configured values
        autoanalysisResultsModel.enableLoad();
        // TODO: Make configureable again
        autoanalysisResultsModel.setSimilarityThreshold(0.95);

        // Get all collections that are selected
        List<Collection> collections = collectionsModel.getModelData().stream()
                .filter(CollectionRowObject::isInclude)
                .map(CollectionRowObject::getCollection)
                .toList();

        autoanalysisResultsModel.setCollections(collections);

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
