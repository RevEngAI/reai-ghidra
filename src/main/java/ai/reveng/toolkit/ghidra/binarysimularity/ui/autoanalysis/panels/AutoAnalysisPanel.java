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
import java.util.stream.StreamSupport;

import javax.swing.JProgressBar;
import javax.swing.JTabbedPane;
import javax.swing.JSplitPane;
import javax.swing.JList;
import javax.swing.AbstractListModel;
import javax.swing.JScrollPane;
import javax.swing.JCheckBox;

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

	/**
	 * Create the panel.
	 */
	public AutoAnalysisPanel(PluginTool tool) {
		this.tool = tool;
		setLayout(new BorderLayout(0, 0));
		setPreferredSize(new Dimension(710, 660));

		JPanel optionsPanel = new JPanel();
		add(optionsPanel);
		optionsPanel.setLayout(new BorderLayout(0, 0));
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		optionsPanel.add(tabbedPane, BorderLayout.NORTH);
		
		JPanel collectionsPanel = new JPanel();
		tabbedPane.addTab("Collections", null, collectionsPanel, null);
		collectionsModel = new CollectionTableModel(tool);
		collectionsPanel.setLayout(new BorderLayout(0, 0));
		collectionsTable = new GFilterTable<CollectionRowObject>(collectionsModel);
		collectionsPanel.add(collectionsTable);

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
		confidenceSlider.setValue(80);
		confidenceSlider.setSnapToTicks(true);
		confidenceSlider.setMinorTickSpacing(5);
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
	
	private String generateRegex(String[] libList) {
		if (libList.length == 0) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		
		for (String s: libList) {
			sb.append(s);
		}
		return sb.toString();
	}
	
	private void performAutoAnalysis() {
		btnStartAnalysis.setEnabled(false);
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

		for (Function func : fm.getFunctions(true)) {
			progressBar.setString("Searching for " + func.getName() + " [" + (cursor+1) + "/" + numFuncs + "]");
			System.out.println("Searching for " + func.getName() + " [" + (cursor+1) + "/" + numFuncs + "]");
			
			FunctionEmbedding fe = bin.getFunctionEmbedding(Long.parseLong(func.getEntryPoint().toString(), 16));
			if (fe == null) {
				cursor++;
				int progress = (int) (((double) cursor / numFuncs) * 100);
				System.out.println("Progress: " + progress);
				progressBar.setValue(progress);
				continue;
			}
			 
//			String[] regex;
//			if (chckbxLibC.isSelected()) {
//				regex = new String[]{"libc"};
//				System.out.println("Autodiscover libc");
//			} else {
//				regex = null;
//			}
			
			res = apiService.nearestSymbols(fe.getEmbedding(), currentBinaryHash, 1, null);

			JSONObject jFunc = res.getJsonArray().getJSONObject(0);
			Double distance = jFunc.getDouble("distance");
			if (distance >= getConfidenceSlider().getValue() / 100) {
				System.out.println(
						"Found symbol '" + jFunc.getString("name") + "' with a confidence of " + distance);
				int transactionID = currentProgram.startTransaction("Rename function from autoanalysis");
				try {
					func.setName(jFunc.getString("name"), SourceType.USER_DEFINED);
					currentProgram.endTransaction(transactionID, true);
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
			cursor++;
			int progress = (int) (((double) cursor / numFuncs) * 100);
			System.out.println("Progress: " + progress);
			progressBar.setValue(progress);
		}
		progressBar.setString("Finished");
		btnStartAnalysis.setEnabled(true);
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
}
