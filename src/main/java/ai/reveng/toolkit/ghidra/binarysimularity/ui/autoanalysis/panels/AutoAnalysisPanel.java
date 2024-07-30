package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.panels;

import java.awt.*;

import javax.swing.*;

import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.CollectionRowObject;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.AutoAnalysisResultsTableModel;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.CollectionTableModel;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatch;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import docking.widgets.table.GFilterTable;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.task.TaskLauncher;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static ai.reveng.toolkit.ghidra.binarysimularity.BinarySimularityPlugin.REVENG_AI_NAMESPACE;

/**
 * Panel for configuring auto analysis options
 */
public class AutoAnalysisPanel extends JPanel {
	private static final long serialVersionUID = 173612485615794790L;
	private JButton btnFetchCollections;
	/**
	 * Sets the threshold for an auto selected symbol
	 */
	private JSlider confidenceSlider;

	private PluginTool tool;
	private JButton btnFetchFunctions;
	private JButton btnApplyAllFilteredResults;

	private GFilterTable<CollectionRowObject> collectionsTable;
	private CollectionTableModel collectionsModel;
	
	private GhidraFilterTable<GhidraFunctionMatch> analysisResultsTable;
	private AutoAnalysisResultsTableModel autoanalysisResultsModel;
	
	private JTabbedPane tabbedPanel;
	private JLabel lblUnsuccessfulAnalysesValue;
	private JLabel lblSuccessfulAnalysesValue;
	private JLabel lblTotalAnalysesValue;
	
//	private AutoAnalysisSummary analysisSummary;
	private JPanel resultsPanel;
	private JLabel lblSkippedAnalysisValue;
	
	private ReaiLoggingService loggingService;
	private JButton btnApplySelectedResults;

	/**
	 * Create the panel.
	 */
	public AutoAnalysisPanel(PluginTool tool) {
		this.tool = tool;
		setLayout(new BorderLayout(0, 0));
		setPreferredSize(new Dimension(1250, 730));
		
		loggingService = tool.getService(ReaiLoggingService.class);
		if (loggingService == null) {
			Msg.error(this, "Unable to access logging service");
		}

		JPanel optionsPanel = new JPanel();
		add(optionsPanel);
		optionsPanel.setLayout(new BorderLayout(0, 0));
		
		tabbedPanel = new JTabbedPane(JTabbedPane.TOP);
		optionsPanel.add(tabbedPanel, BorderLayout.NORTH);
		


		JPanel resultsPanel = this.buildResultsPanel();
		tabbedPanel.addTab("Results", null, resultsPanel, null);

		// TODO: Collections panel works in principle, but the API is not really available yet
//		JPanel collectionsPanel = this.buildCollectionsPanel();
//		tabbedPanel.addTab("Collections", null, collectionsPanel, null);
	}

	private JSlider buildConfidenceSlider(JLabel lblConfidenceValue) {
		var confidenceSlider = new JSlider();
		confidenceSlider.setMajorTickSpacing(10);
		confidenceSlider.addChangeListener(e -> {
			int sliderValue = confidenceSlider.getValue();
			if (btnFetchFunctions != null){
				btnFetchFunctions.setEnabled(true);
			}
			lblConfidenceValue.setText(Integer.toString(sliderValue));
		});
		confidenceSlider.setPaintLabels(true);
		confidenceSlider.setValue(99);
		confidenceSlider.setSnapToTicks(true);
		confidenceSlider.setMinorTickSpacing(1);
		confidenceSlider.setPaintTicks(true);
		return confidenceSlider;
	}

	private JPanel buildResultsPanel() {
		JPanel resultsPanel = new JPanel();
		resultsPanel.setLayout(new BorderLayout(0, 0));

		autoanalysisResultsModel = new AutoAnalysisResultsTableModel(tool);
		analysisResultsTable = new GhidraFilterTable<GhidraFunctionMatch>(autoanalysisResultsModel);

//		analysisResultsTable.setBounds(0, 0, 100, 100);
		analysisResultsTable.setMinimumSize(null);
		analysisResultsTable.installNavigation(tool);
		resultsPanel.add(analysisResultsTable, BorderLayout.NORTH);

//		JPanel actionPanel = new JPanel();
//		add(actionPanel, BorderLayout.SOUTH);
//		actionPanel.setLayout(new BorderLayout(0, 0));

		btnFetchFunctions = new JButton("Fetch Similar Functions");
		btnFetchFunctions.addActionListener(e -> {
			if (!btnFetchFunctions.isEnabled()) {
				return;
			}
			TaskLauncher.launchModal("Fetch Similar Functions", () -> {
				try {
					loadAutoRenameResults();
				} catch (Exception exc) {
					Msg.showError(this, btnFetchFunctions,
							ReaiPluginPackage.WINDOW_PREFIX + "Auto Analysis Error", exc.getMessage(), exc);
					loggingService.error(exc.getMessage());
				}
				btnApplyAllFilteredResults.setEnabled(true);
				btnApplySelectedResults.setEnabled(true);
			});
		});

		btnApplySelectedResults = new JButton("Apply Selected Results");
		btnApplySelectedResults.setEnabled(false);
		btnApplySelectedResults.addActionListener( e -> {
			applyAutoRenameResults(autoanalysisResultsModel.getLastSelectedObjects());
		});

		btnApplyAllFilteredResults = new JButton("Apply Filtered Results");
		btnApplyAllFilteredResults.setEnabled(false);
		btnApplyAllFilteredResults.addActionListener(e -> {
			applyAutoRenameResults(autoanalysisResultsModel.getModelData());
		});




		JPanel resultBtnPnl = new JPanel(new FlowLayout(FlowLayout.CENTER));
		resultBtnPnl.add(btnFetchFunctions);
		resultBtnPnl.add(btnApplySelectedResults);
		resultBtnPnl.add(btnApplyAllFilteredResults);

		resultsPanel.add(resultBtnPnl, BorderLayout.SOUTH);

		JPanel confidencePanel = new JPanel();
		confidencePanel.setLayout(new BorderLayout(0, 0));

		JPanel valuePanel = new JPanel();
		confidencePanel.add(valuePanel, BorderLayout.NORTH);

		JLabel lblConfidence = new JLabel("Confidence:");
		valuePanel.add(lblConfidence);

		JLabel lblConfidenceValue = new JLabel("\n");
		valuePanel.add(lblConfidenceValue);


		confidenceSlider = this.buildConfidenceSlider(lblConfidenceValue);
		confidencePanel.add(confidenceSlider);

		resultsPanel.add(confidencePanel, BorderLayout.CENTER);



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
		btnFetchCollections.addActionListener( e -> {
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

	private void loadAutoRenameResults(){
		autoanalysisResultsModel.clearData();
		btnFetchFunctions.setEnabled(false);
		GhidraRevengService apiService = tool.getService(GhidraRevengService.class);
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager.getCurrentProgram();

		var thresholdConfidence = (double) getConfidenceSlider().getValue() / 100;


		Map<Function, List<GhidraFunctionMatch>> r = apiService.getSimilarFunctions(currentProgram, 1, 1 - thresholdConfidence);

		r.values().stream()
				// Filter out functions that have no matches
				.filter( list -> !list.isEmpty())
				// Get the best match
				.map( list -> list.get(0))
				// Filter out matches that are below the threshold
				.filter( match -> match.confidence() >= thresholdConfidence)
				// Add the best matches to the table
				.forEach(autoanalysisResultsModel::addObject);
	}


	private void applyAutoRenameResults(List<GhidraFunctionMatch> matchesToApply){
		ProgramManager programManager = tool.getService(ProgramManager.class);

		Program currentProgram = programManager.getCurrentProgram();

		/*
		 * using getFunctionCount() also returns external functions so our count is wrong for the progress.
		 * Instead, we just count the number of entries that are contained in the iterator
		 */
		FunctionManager fm = currentProgram.getFunctionManager();
//		long numFuncs = StreamSupport.stream(fm.getFunctions(true).spliterator(), false).count();
//		int cursor = 0;

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
				row -> {
                    try {
						var func = row.function();
						var libraryNamespace = currentProgram.getSymbolTable().getOrCreateNameSpace(
								finalRevengMatchNamespace,
								row.functionMatch().nearest_neighbor_binary_name(),
								SourceType.USER_DEFINED);

						func.setParentNamespace(libraryNamespace);
						if (func.getName().startsWith("FUN_")) {
							func.setName(row.functionMatch().nearest_neighbor_function_name(), SourceType.USER_DEFINED);
						}
                    } catch (DuplicateNameException | InvalidInputException | CircularDependencyException e) {
						Msg.showError(this, btnFetchFunctions,
								ReaiPluginPackage.WINDOW_PREFIX + "Rename Function Error", e.getMessage(), e);
                    }
                }
		);

		currentProgram.endTransaction(transactionID, true);
	}

	protected JSlider getConfidenceSlider() {
		return confidenceSlider;
	}
}
