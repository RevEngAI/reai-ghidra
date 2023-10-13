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

import org.json.JSONObject;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import ai.reveng.toolkit.ghidra.core.services.api.types.Binary;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionEmbedding;
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
import javax.swing.JProgressBar;

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

	/**
	 * Create the panel.
	 */
	public AutoAnalysisPanel(PluginTool tool) {
		this.tool = tool;
		setLayout(new BorderLayout(0, 0));
		setPreferredSize(new Dimension(455, 280));

		JPanel titlePanel = new JPanel();
		add(titlePanel, BorderLayout.NORTH);

		JLabel lblTitle = new JLabel("Auto Analyse");
		titlePanel.add(lblTitle);

		JPanel optionsPanel = new JPanel();
		add(optionsPanel);
		optionsPanel.setLayout(new BorderLayout(0, 0));

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
		
		int numFuncs = fm.getFunctionCount();
		int cursor = 0;
		progressBar.setValue(0);

		Binary bin = new Binary(res.getJsonArray());

		for (Function func : fm.getFunctions(true)) {
			progressBar.setString("Searching for " + func.getName() + " [" + (cursor+1) + "/" + numFuncs + "]");
			FunctionEmbedding fe = bin.getFunctionEmbedding(Long.parseLong(func.getEntryPoint().toString(), 16));
			if (fe == null)
				continue;
			res = apiService.nearestSymbols(fe.getEmbedding(), currentBinaryHash, 1, null);

			JSONObject jFunc = res.getJsonArray().getJSONObject(0);
			Double distance = 1 - jFunc.getDouble("distance");
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
