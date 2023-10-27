package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.panels;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import javax.swing.SwingWorker;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.json.JSONArray;
import org.json.JSONObject;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.AutoAnalysisResultsRowObject;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.AutoAnalysisResultsTableModel;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.AutoAnalysisSummary;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.CollectionRowObject;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.CollectionTableModel;
import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import ai.reveng.toolkit.ghidra.core.services.api.types.Binary;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionEmbedding;
import docking.widgets.table.GFilterTable;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.StreamSupport;

import javax.swing.JProgressBar;
import javax.swing.JTabbedPane;
import javax.swing.JSplitPane;
import javax.swing.JList;
import javax.swing.AbstractListModel;
import javax.swing.JScrollPane;
import javax.swing.JCheckBox;
import java.awt.GridLayout;
import javax.swing.BoxLayout;
import javax.swing.SwingConstants;
import java.awt.FlowLayout;
import java.awt.Component;

/**
 * Panel for configuring auto analysis options
 */
public class AutoAnalysisPanel extends JPanel {
	private static final long serialVersionUID = 173612485615794790L;
	/**
	 * Sets the threshold for an auto selected symbol
	 */
	private JSlider confidenceSlider;
	private JProgressBar progressBar;
	
	private PluginTool tool;
	private JButton btnStartAnalysis;
	
	private GFilterTable<CollectionRowObject> collectionsTable;
	private CollectionTableModel collectionsModel;
	
	private GFilterTable<AutoAnalysisResultsRowObject> analysisResultsTable;
	private AutoAnalysisResultsTableModel autoanalysisResultsModel;
	
	private JTabbedPane tabbedPanel;
	private JLabel lblUnsuccessfulAnalysesValue;
	private JLabel lblSuccessfulAnalysesValue;
	private JLabel lblTotalAnalysesValue;
	
	private AutoAnalysisSummary analysisSummary;
	private JPanel resultsPanel;
	private JLabel lblSkippedAnalysisValue;

	/**
	 * Create the panel.
	 */
	public AutoAnalysisPanel(PluginTool tool) {
		this.tool = tool;
		setLayout(new BorderLayout(0, 0));
		setPreferredSize(new Dimension(1250, 730));

		JPanel optionsPanel = new JPanel();
		add(optionsPanel);
		optionsPanel.setLayout(new BorderLayout(0, 0));
		
		tabbedPanel = new JTabbedPane(JTabbedPane.TOP);
		optionsPanel.add(tabbedPanel, BorderLayout.NORTH);
		
		JPanel collectionsPanel = new JPanel();
		tabbedPanel.addTab("Collections", null, collectionsPanel, null);
		collectionsModel = new CollectionTableModel(tool);
		collectionsPanel.setLayout(new BorderLayout(0, 0));
		collectionsTable = new GFilterTable<CollectionRowObject>(collectionsModel);
		collectionsPanel.add(collectionsTable);
		
		resultsPanel = new JPanel();
		tabbedPanel.addTab("Results", null, resultsPanel, null);
		resultsPanel.setLayout(new BorderLayout(0, 0));
		
		autoanalysisResultsModel = new AutoAnalysisResultsTableModel(tool);
		analysisResultsTable = new GFilterTable<AutoAnalysisResultsRowObject>(autoanalysisResultsModel);
		resultsPanel.add(analysisResultsTable, BorderLayout.CENTER);
		
		JPanel summaryPanel = new JPanel();
		resultsPanel.add(summaryPanel, BorderLayout.SOUTH);
		summaryPanel.setLayout(new BoxLayout(summaryPanel, BoxLayout.Y_AXIS));
		
		JLabel lblSummaryTitle = new JLabel("Analysis Summary:");
		lblSummaryTitle.setAlignmentX(Component.CENTER_ALIGNMENT);
		lblSummaryTitle.setHorizontalAlignment(SwingConstants.CENTER);
		summaryPanel.add(lblSummaryTitle);
		
		JPanel statsPanel = new JPanel();
		summaryPanel.add(statsPanel);
		statsPanel.setLayout(new GridLayout(4, 2, 3, 0));
		
		JLabel lblAnalysisedFunctions = new JLabel("Total Functions Analysed:");
		lblAnalysisedFunctions.setHorizontalAlignment(SwingConstants.RIGHT);
		statsPanel.add(lblAnalysisedFunctions);
		
		lblTotalAnalysesValue = new JLabel("0");
		statsPanel.add(lblTotalAnalysesValue);
		
		JLabel lblSuccessfulAnalyses = new JLabel("Successful Analyses:");
		lblSuccessfulAnalyses.setHorizontalAlignment(SwingConstants.RIGHT);
		statsPanel.add(lblSuccessfulAnalyses);
		
		lblSuccessfulAnalysesValue = new JLabel("0");
		statsPanel.add(lblSuccessfulAnalysesValue);
		
		JLabel lblSkippedAnalysis = new JLabel("Skipped Analyses:");
		lblSkippedAnalysis.setHorizontalAlignment(SwingConstants.RIGHT);
		statsPanel.add(lblSkippedAnalysis);
		
		lblSkippedAnalysisValue = new JLabel("0");
		statsPanel.add(lblSkippedAnalysisValue);
		
		JLabel lblUnsuccessfulAnalyses = new JLabel("Errored Analyses:");
		lblUnsuccessfulAnalyses.setHorizontalAlignment(SwingConstants.RIGHT);
		statsPanel.add(lblUnsuccessfulAnalyses);
		
		lblUnsuccessfulAnalysesValue = new JLabel("0");
		statsPanel.add(lblUnsuccessfulAnalysesValue);
		tabbedPanel.setEnabledAt(1, false);

		JPanel confidencePanel = new JPanel();
		optionsPanel.add(confidencePanel, BorderLayout.SOUTH);
		confidencePanel.setLayout(new BorderLayout(0, 0));

		JPanel valuePanel = new JPanel();
		confidencePanel.add(valuePanel, BorderLayout.NORTH);

		JLabel lblConfidence = new JLabel("Confidence:");
		valuePanel.add(lblConfidence);

		JLabel lblConfidenceValue = new JLabel("\n");
		valuePanel.add(lblConfidenceValue);

		confidenceSlider = new JSlider();
		confidenceSlider.setMajorTickSpacing(10);
		confidenceSlider.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				int sliderValue = confidenceSlider.getValue();
				lblConfidenceValue.setText(Integer.toString(sliderValue));
			}
		});
		confidenceSlider.setPaintLabels(true);
		confidenceSlider.setValue(99);
		confidenceSlider.setSnapToTicks(true);
		confidenceSlider.setMinorTickSpacing(1);
		confidenceSlider.setPaintTicks(true);
		confidencePanel.add(confidenceSlider);

		JPanel actionPanel = new JPanel();
		add(actionPanel, BorderLayout.SOUTH);
		actionPanel.setLayout(new BorderLayout(0, 0));

		btnStartAnalysis = new JButton("Start");
		btnStartAnalysis.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (!btnStartAnalysis.isEnabled()) {
					return;
				}
				SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
					@Override
					protected Void doInBackground() throws Exception {
						performAutoAnalysis();
						return null;
					}
				};
				worker.execute();
			}
		});
		
		progressBar = new JProgressBar();
		progressBar.setStringPainted(true);
		actionPanel.add(progressBar, BorderLayout.NORTH);
		actionPanel.add(btnStartAnalysis, BorderLayout.SOUTH);
	}
	
	private String generateRegex(List<String> collections) {
		if (collections.size() == 0) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		
//		sb.append("\\b(?:");
		
		boolean firstItem = true;
		for (String s: collections) {
			if (!firstItem)
				sb.append("|");
			sb.append(s);
			firstItem = false;
		}
//		sb.append(")\\w*\\b");
		return sb.toString();
	}
	
	private void performAutoAnalysis() {		
		analysisSummary = new AutoAnalysisSummary();
		List<AutoAnalysisResultsRowObject> tableEntries = new ArrayList<AutoAnalysisResultsRowObject>();
		btnStartAnalysis.setEnabled(false);
		getTabbedPanel().setEnabledAt(1, false);
		ApiService apiService = tool.getService(ApiService.class);
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager.getCurrentProgram();
		FunctionManager fm = currentProgram.getFunctionManager();

		String currentBinaryHash = currentProgram.getExecutableSHA256();

		ApiResponse res = apiService.embeddings(currentBinaryHash);

		if (res.getStatusCode() > 299) {
			Msg.showError(fm, null, ReaiPluginPackage.WINDOW_PREFIX + "Auto Analysis",
					res.getJsonObject().get("error"));
			return;
		}
		
		/*
		 * using getFunctionCount() also returns external functions so our count is wrong for the progress.
		 * Instead we just count the number of entries that are contained in the iterator
		 */
		long numFuncs = StreamSupport.stream(fm.getFunctions(true).spliterator(), false).count();
		int cursor = 0;
		progressBar.setValue(0);

		Binary bin = new Binary(res.getJsonArray());
		
		boolean log_unsuc = numFuncs > 1000 ? false : true;
		for (Function func : fm.getFunctions(true)) {
			progressBar.setString("Searching for " + func.getName() + " [" + (cursor+1) + "/" + numFuncs + "]");
			System.out.println("Searching for " + func.getName() + " [" + (cursor+1) + "/" + numFuncs + "]");
			analysisSummary.incrementStat("total_analyses");
			
			FunctionEmbedding fe = bin.getFunctionEmbedding(Long.parseLong(func.getEntryPoint().toString(), 16));
			if (fe == null) {
				cursor++;
				int progress = (int) (((double) cursor / numFuncs) * 100);
				System.out.println("Progress: " + progress);
				progressBar.setValue(progress);
				analysisSummary.incrementStat("skipped_analyses");
				if (log_unsuc) {
					tableEntries.add(new AutoAnalysisResultsRowObject(func.getName(), "N/A", false, "No Function Embedding Found"));
				}
				continue;
			}
			 
			String regex = generateRegex(collectionsModel.getSelectedCollections());
			
			res = apiService.nearestSymbols(fe.getEmbedding(), currentBinaryHash, 1, regex);
			
			if (res.getStatusCode() != 200) {
				cursor++;
				int progress = (int) (((double) cursor / numFuncs) * 100);
				System.out.println("Progress: " + progress);
				progressBar.setValue(progress);
				analysisSummary.incrementStat("unsuccessful_analyses");
				if (log_unsuc) {
					tableEntries.add(new AutoAnalysisResultsRowObject(func.getName(), "N/A", false, res.getResponseBody()));
				}
				continue;
			}
			
			String srcSymbol = func.getName();
			JSONObject jFunc = res.getJsonArray().getJSONObject(0);
			Double distance = jFunc.getDouble("distance");
			if (distance >= getConfidenceSlider().getValue() / 100) {
				System.out.println(
						"Found symbol '" + jFunc.getString("name") + "' with a confidence of " + distance);
				int transactionID = currentProgram.startTransaction("Rename function from autoanalysis");
				try {
					func.setName(jFunc.getString("name"), SourceType.USER_DEFINED);
					currentProgram.endTransaction(transactionID, true);
					tableEntries.add(new AutoAnalysisResultsRowObject(srcSymbol,jFunc.getString("name") + " ("+ jFunc.getString("binary_name") + ")", true, "Renamed with confidence of '" + distance));
				} catch (DuplicateNameException exc) {
					System.err.println("Symbol already exists");
					currentProgram.endTransaction(transactionID, false);
					Msg.showError(bin, btnStartAnalysis,
							ReaiPluginPackage.WINDOW_PREFIX + "Rename Function Error", exc.getMessage());
				} catch (Exception exc) {
					currentProgram.endTransaction(transactionID, false);
					System.err.println("Unknown Error");
				}
			}
			analysisSummary.incrementStat("successful_analyses");
			cursor++;
			int progress = (int) (((double) cursor / numFuncs) * 100);
			System.out.println("Progress: " + progress);
			progressBar.setValue(progress);
		}
		progressBar.setString("Finished");
		btnStartAnalysis.setEnabled(true);
		autoanalysisResultsModel.batch(tableEntries);
		lblTotalAnalysesValue.setText(Integer.toString(analysisSummary.getStat("total_analyses")));
		lblSuccessfulAnalysesValue.setText(Integer.toString(analysisSummary.getStat("successful_analyses")));
		lblSkippedAnalysisValue.setText(Integer.toString(analysisSummary.getStat("skipped_analyses")));
		lblUnsuccessfulAnalysesValue.setText(Integer.toString(analysisSummary.getStat("unsuccessful_analyses")));
		getTabbedPanel().setEnabledAt(1, true);
		
	}

	protected JSlider getConfidenceSlider() {
		return confidenceSlider;
	}
	protected JProgressBar getProgressBar() {
		return progressBar;
	}
	protected JButton getBtnStartAnalysis() {
		return btnStartAnalysis;
	}
	protected JTabbedPane getTabbedPanel() {
		return tabbedPanel;
	}
	protected JLabel getLblUnsuccessfulAnalysesValue() {
		return lblUnsuccessfulAnalysesValue;
	}
	protected JLabel getLblSuccessfulAnalysesValue() {
		return lblSuccessfulAnalysesValue;
	}
	protected JLabel getLblTotalAnalysesValue() {
		return lblTotalAnalysesValue;
	}
	protected JLabel getLblSkippedAnalysisValue() {
		return lblSkippedAnalysisValue;
	}
}
