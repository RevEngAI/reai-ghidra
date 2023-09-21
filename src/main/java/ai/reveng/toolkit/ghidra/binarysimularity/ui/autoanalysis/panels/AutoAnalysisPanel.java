package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.panels;

import java.awt.BorderLayout;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.json.JSONException;
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
import ghidra.util.exception.InvalidInputException;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class AutoAnalysisPanel extends JPanel {
	private JSlider confidenceSlider;

	/**
	 * Create the panel.
	 */
	public AutoAnalysisPanel(PluginTool tool) {
		setLayout(new BorderLayout(0, 0));

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

		JButton btnStartAnalysis = new JButton("Start");
		btnStartAnalysis.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				ApiService apiService = tool.getService(ApiService.class);
				ProgramManager programManager = tool.getService(ProgramManager.class);
				Program currentProgram = programManager.getCurrentProgram();
				FunctionManager fm = currentProgram.getFunctionManager();
				
				String currentBinaryHash = currentProgram.getExecutableSHA256();

				ApiResponse res = apiService.embeddings(currentBinaryHash);

				if (res.getStatusCode() > 299) {
					Msg.showError(fm, null, ReaiPluginPackage.WINDOW_PREFIX + "Auto Analysis", res.getJsonObject().get("error"));
					return;
				}

				Binary bin = new Binary(res.getJsonArray());
				
				for (Function func : fm.getFunctions(true)) {
					FunctionEmbedding fe = bin.getFunctionEmbedding(func.getName());
					if (fe == null)
						continue;
					res = apiService.nearestSymbols(fe.getEmbedding(), currentBinaryHash, 1, null);
					
					JSONObject jFunc = res.getJsonArray().getJSONObject(0);
					Double distance = 1 - jFunc.getDouble("distance");
					if (distance >= getConfidenceSlider().getValue() / 100) {
						System.out.println("Found symbol '"+jFunc.getString("name")+"' with a confidence of " + distance);
						int transactionID = currentProgram.startTransaction("Rename function from autoanalysis");
						try {
							func.setName(jFunc.getString("name"), SourceType.USER_DEFINED);
							currentProgram.endTransaction(transactionID, true);
						} catch (DuplicateNameException exc) {
							System.err.println("Symbol already exists");
							currentProgram.endTransaction(transactionID, false);
							Msg.showError(bin, btnStartAnalysis, ReaiPluginPackage.WINDOW_PREFIX+"Rename Function Error", exc.getMessage());
						} catch (Exception exc) {
							currentProgram.endTransaction(transactionID, false);
							System.err.println("Unknown Error");
						}
					}
				}
			}
		});
		actionPanel.add(btnStartAnalysis, BorderLayout.SOUTH);
	}

	protected JSlider getConfidenceSlider() {
		return confidenceSlider;
	}
}
