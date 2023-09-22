package ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.panels;

import javax.swing.JPanel;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.models.CanidateFunctionModel;
import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import ai.reveng.toolkit.ghidra.core.services.api.types.Binary;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionEmbedding;

import java.awt.BorderLayout;

import docking.widgets.table.GTable;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import javax.swing.JScrollPane;

import org.json.JSONArray;
import org.json.JSONObject;
import javax.swing.JButton;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.BoxLayout;
import javax.swing.JSeparator;
import javax.swing.SwingWorker;
import javax.swing.JTextField;
import javax.swing.JLabel;
import java.awt.Component;
import javax.swing.JCheckBox;
import java.awt.FlowLayout;

/**
 * GUI for displaying results from a FunctionSimularity request
 */
public class RenameFunctionFromSimilarFunctionsPanel extends JPanel {
	private static final long serialVersionUID = -7365592104915627273L;
	private GTable canidateFunctionsTable;
	private CanidateFunctionModel cfm = new CanidateFunctionModel();
	private Function functionUnderReview;
	private ApiService apiService;
	private String currentBinaryHash;
	private JScrollPane canidateFunctionsScrollPanel;
	private JPanel actionButtonPanel;
	private JPanel parametersPanel;
	private JSeparator separator_1;
	private JPanel numResultsPanel;
	private JTextField numResultsTf;
	private JLabel lblNumResults;
	private JPanel debugSymbolsCheckPanel;
	private JCheckBox chckbxNewCheckBox;
	private JLabel lblParamsPanelTitle;

	public RenameFunctionFromSimilarFunctionsPanel(Function functionUnderReview, PluginTool tool) {
		this.functionUnderReview = functionUnderReview;
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager.getCurrentProgram();
		apiService = tool.getService(ApiService.class);
		currentBinaryHash = currentProgram.getExecutableSHA256();

		setLayout(new BorderLayout(0, 0));

		actionButtonPanel = new JPanel();
		add(actionButtonPanel, BorderLayout.WEST);

		JButton btnRename = new JButton("Rename");
		btnRename.setAlignmentX(Component.CENTER_ALIGNMENT);
		btnRename.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {

				int tableCursor = canidateFunctionsTable.getSelectedRow();

				if (tableCursor != -1) {
					int transactionID = currentProgram.startTransaction("Rename function from similar functions");
					try {
						functionUnderReview.setName((String) canidateFunctionsTable.getValueAt(tableCursor, 0),
								SourceType.USER_DEFINED);
						currentProgram.endTransaction(transactionID, true);
					} catch (DuplicateNameException exc) {
						System.err.println("Symbol already exists");
						currentProgram.endTransaction(transactionID, false);
						Msg.showError(actionButtonPanel, btnRename,
								ReaiPluginPackage.WINDOW_PREFIX + "Rename Function Error", exc.getMessage());
					} catch (Exception exc) {
						currentProgram.endTransaction(transactionID, false);
						System.err.println("Unknown Error");
					}
				}
			}
		});
		actionButtonPanel.setLayout(new BoxLayout(actionButtonPanel, BoxLayout.Y_AXIS));
		actionButtonPanel.add(btnRename);

		JSeparator separator = new JSeparator();
		actionButtonPanel.add(separator);

		parametersPanel = new JPanel();
		actionButtonPanel.add(parametersPanel);
		parametersPanel.setLayout(new BoxLayout(parametersPanel, BoxLayout.Y_AXIS));

		lblParamsPanelTitle = new JLabel("Symbol Options");
		lblParamsPanelTitle.setAlignmentX(Component.CENTER_ALIGNMENT);
		parametersPanel.add(lblParamsPanelTitle);

		debugSymbolsCheckPanel = new JPanel();
		parametersPanel.add(debugSymbolsCheckPanel);
		debugSymbolsCheckPanel.setLayout(new BoxLayout(debugSymbolsCheckPanel, BoxLayout.Y_AXIS));

		chckbxNewCheckBox = new JCheckBox("Use Debug Symbols");
		chckbxNewCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT);
		debugSymbolsCheckPanel.add(chckbxNewCheckBox);

		numResultsPanel = new JPanel();
		parametersPanel.add(numResultsPanel);
		numResultsPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

		lblNumResults = new JLabel("Results");
		numResultsPanel.add(lblNumResults);

		numResultsTf = new JTextField();
		numResultsTf.setText("5");
		lblNumResults.setLabelFor(numResultsTf);
		numResultsPanel.add(numResultsTf);
		numResultsTf.setColumns(3);

		JButton btnRefresh = new JButton("Refresh");
		btnRefresh.setAlignmentX(Component.CENTER_ALIGNMENT);
		btnRefresh.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				populateTableResults();
			}
		});

		separator_1 = new JSeparator();
		actionButtonPanel.add(separator_1);
		actionButtonPanel.add(btnRefresh);

		canidateFunctionsScrollPanel = new JScrollPane();
		add(canidateFunctionsScrollPanel, BorderLayout.CENTER);

		canidateFunctionsTable = new GTable(cfm);
		canidateFunctionsScrollPanel.setViewportView(canidateFunctionsTable);

		SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
			@Override
			protected Void doInBackground() throws Exception {
				populateTableResults();
				return null;
			}
		};

		worker.execute();
	}

	private void populateTableResults() {
		cfm.clearData();

		ApiResponse res = apiService.embeddings(currentBinaryHash);

		if (res.getStatusCode() > 299) {
			Msg.showError(actionButtonPanel, canidateFunctionsScrollPanel,
					ReaiPluginPackage.WINDOW_PREFIX + "Function Simularity", res.getJsonObject().get("error"));
			return;
		}

		Binary bin = new Binary(res.getJsonArray());

		FunctionEmbedding fe = bin.getFunctionEmbedding(functionUnderReview.getName());

		if (fe == null) {
			Msg.showError(bin, canidateFunctionsScrollPanel, ReaiPluginPackage.WINDOW_PREFIX + "Find Similar Functions",
					"No similar functions found");
			return;
		}

		res = apiService.nearestSymbols(fe.getEmbedding(), currentBinaryHash, Integer.parseInt(numResultsTf.getText()),
				null);

		System.out.println(fe.getEmbedding());

		JSONArray jCanidateFunctions = res.getJsonArray();

		for (int i = 0; i < jCanidateFunctions.length(); i++) {
			JSONObject jCanidateFunction = jCanidateFunctions.getJSONObject(i);
			cfm.addRow(new String[] { jCanidateFunction.getString("name"), jCanidateFunction.get("distance").toString(),
					jCanidateFunction.getString("binary_name") });
		}
	}

	protected JScrollPane getCanidateFunctionsScrollPanel() {
		return canidateFunctionsScrollPanel;
	}

	protected JPanel getActionButtonPanel() {
		return actionButtonPanel;
	}

	protected JCheckBox getChckbxNewCheckBox() {
		return chckbxNewCheckBox;
	}

	protected JTextField getNumResultsTf() {
		return numResultsTf;
	}
}
