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
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.swing.JProgressBar;
import javax.swing.SwingConstants;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

/**
 * GUI for displaying results from a FunctionSimularity request
 */
public class RenameFunctionFromSimilarFunctionsPanel extends JPanel {
	private static final long serialVersionUID = -7365592104915627273L;
	private static final String PROGRESS_DEFAULT_MSG = "Waiting to Fetch";
	private static final String PROGRESS_FETCHING_MSG = "Fetching Results";
	private static final String PROGRESS_GOT_RESULTS_MSG = "Done";
	private GTable canidateFunctionsTable;
	private CanidateFunctionModel cfm = new CanidateFunctionModel();
	private Function functionUnderReview;
	private ApiService apiService;
	private String currentBinaryHash;
	private JScrollPane canidateFunctionsScrollPanel;
	private JPanel actionButtonPanel;
	private JPanel parametersPanel;
	private JSeparator separator;
	private JPanel numResultsPanel;
	private JTextField numResultsTf;
	private JLabel lblNumResults;
	private JPanel debugSymbolsCheckPanel;
	private JCheckBox chckbxNewCheckBox;
	private JLabel lblParamsPanelTitle;
	private Lock lock = new ReentrantLock();
	private JProgressBar progressBar;
	private JPanel progressPanel;
	private JLabel lblProgressStatusText;
	private JButton btnRefresh;

	public RenameFunctionFromSimilarFunctionsPanel(Function functionUnderReview, PluginTool tool) {
		this.functionUnderReview = functionUnderReview;
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager.getCurrentProgram();
		apiService = tool.getService(ApiService.class);
		currentBinaryHash = currentProgram.getExecutableSHA256();

		setLayout(new BorderLayout(0, 0));

		actionButtonPanel = new JPanel();
		add(actionButtonPanel, BorderLayout.WEST);
		actionButtonPanel.setLayout(new BoxLayout(actionButtonPanel, BoxLayout.Y_AXIS));

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

		btnRefresh = new JButton("Fetch Results");
		btnRefresh.setEnabled(false);
		btnRefresh.setAlignmentX(Component.CENTER_ALIGNMENT);
		btnRefresh.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (!btnRefresh.isEnabled()) {
					return;
				}
				SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
					@Override
					protected Void doInBackground() throws Exception {
						populateTableResults();
						return null;
					}
				};
				worker.execute();
			}
		});

		separator = new JSeparator();
		actionButtonPanel.add(separator);

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

		progressPanel = new JPanel();
		actionButtonPanel.add(progressPanel);
		progressPanel.setLayout(new BoxLayout(progressPanel, BoxLayout.Y_AXIS));

		progressBar = new JProgressBar();
		progressPanel.add(progressBar);

		lblProgressStatusText = new JLabel("Waiting to Fetch");
		lblProgressStatusText.setAlignmentX(Component.CENTER_ALIGNMENT);
		lblProgressStatusText.setHorizontalAlignment(SwingConstants.CENTER);
		progressPanel.add(lblProgressStatusText);

		JSeparator separator_1 = new JSeparator();
		actionButtonPanel.add(separator_1);
		actionButtonPanel.add(btnRename);
		actionButtonPanel.add(btnRefresh);

		canidateFunctionsScrollPanel = new JScrollPane();
		add(canidateFunctionsScrollPanel, BorderLayout.CENTER);

		canidateFunctionsTable = new GTable(cfm);
		canidateFunctionsTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent e) {
				System.out.println("pressed a key");
				char keyChar = e.getKeyChar();
				int modifiers = e.getModifiersEx();
				// Ctrl+C (or Cmd+C on macOS) was pressed
				if ((modifiers & KeyEvent.CTRL_DOWN_MASK) != 0 && keyChar == 'c') {
					int tableRowCursor = canidateFunctionsTable.getSelectedRow();
					int tableColCursor = canidateFunctionsTable.getSelectedColumn();
					String value = (String) canidateFunctionsTable.getValueAt(tableRowCursor, tableColCursor);
					Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
					System.out.println("Copied: "+value);
					StringSelection selection = new StringSelection(value);
					clipboard.setContents(selection, null);
				}
			}
		});
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
		lock.lock();
		btnRefresh.setEnabled(false);
		try {
			System.out.println("Starting fetch");
			lblProgressStatusText.setText(PROGRESS_FETCHING_MSG);
			progressBar.setValue(25);
			cfm.clearData();

			ApiResponse res = apiService.embeddings(currentBinaryHash);

			if (res.getStatusCode() > 299) {
				Msg.showError(actionButtonPanel, canidateFunctionsScrollPanel,
						ReaiPluginPackage.WINDOW_PREFIX + "Function Simularity", res.getJsonObject().get("error"));
				return;
			}

			progressBar.setValue(50);

			Binary bin = new Binary(res.getJsonArray());

			FunctionEmbedding fe = bin
					.getFunctionEmbedding(Long.parseLong(functionUnderReview.getEntryPoint().toString(), 16));

			if (fe == null) {
				Msg.showError(bin, canidateFunctionsScrollPanel,
						ReaiPluginPackage.WINDOW_PREFIX + "Find Similar Functions", "No similar functions found");
				return;
			}

			res = apiService.nearestSymbols(fe.getEmbedding(), currentBinaryHash,
					Integer.parseInt(numResultsTf.getText()), null);

			System.out.println(fe.getEmbedding());

			JSONArray jCanidateFunctions = res.getJsonArray();

			progressBar.setValue(75);

			for (int i = 0; i < jCanidateFunctions.length(); i++) {
				JSONObject jCanidateFunction = jCanidateFunctions.getJSONObject(i);
				cfm.addRow(new String[] { jCanidateFunction.getString("name"),
						jCanidateFunction.get("distance").toString(), jCanidateFunction.getString("binary_name") });
			}
		} finally {
			progressBar.setValue(100);
			lblProgressStatusText.setText(PROGRESS_GOT_RESULTS_MSG);
			btnRefresh.setEnabled(true);
			lock.unlock();
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

	protected JProgressBar getProgressBar() {
		return progressBar;
	}

	protected JLabel getLblProgressStatusText() {
		return lblProgressStatusText;
	}

	protected JButton getBtnRefresh() {
		return btnRefresh;
	}
}
