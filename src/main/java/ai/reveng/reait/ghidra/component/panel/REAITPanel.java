package ai.reveng.reait.ghidra.component.panel;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import org.json.JSONArray;
import org.json.JSONObject;

import ai.reveng.reait.REAITConfig;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.ghidra.component.AutoAnalyseDockableDialog;
import ai.reveng.reait.ghidra.component.ConfigureDockableDialog;
import ai.reveng.reait.ghidra.component.model.AnalysisStatusTableModel;
import ai.reveng.reait.ghidra.component.model.CollectionsTableModel;
import ai.reveng.reait.ghidra.task.DeleteBinaryTask;
import ai.reveng.reait.ghidra.task.GetAnalysesStatusTask;
import ai.reveng.reait.ghidra.task.GetBinaryEmbeddingsTask;
import ai.reveng.reait.ghidra.task.ReadConfigFileTask;
import ai.reveng.reait.ghidra.task.TaskCallback;
import ai.reveng.reait.ghidra.task.UploadCurrentBinaryTask;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.BoxLayout;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.JTabbedPane;
import java.awt.FlowLayout;

public class REAITPanel extends JPanel {
	private static final long serialVersionUID = -9128086339205968930L;
	private JTextField txtAPIKey;
	private JTextField txtStatus;
	private PluginTool plugin;

	private TaskCallback<Boolean> readConfigFileCallback;
	private TaskCallback<String> uploadBinaryCallback;
	private TaskCallback<String> deleteBinaryCallback;
	private TaskCallback<JSONArray> getAnalysesCallback;
	private TaskCallback<JSONArray> getBinaryEmbeddingsCallback;

	private int tableCursor;

	private JTable analysisTable;
	private JTable collectionsTable;

	/**
	 * Create the panel.
	 */
	public REAITPanel(PluginTool plugin) {
		this.plugin = plugin;

		setPreferredSize(new Dimension(640, 330));

		AnalysisStatusTableModel analysisTableModel = new AnalysisStatusTableModel();
		CollectionsTableModel collectionsTableModel = new CollectionsTableModel();
		

		readConfigFileCallback = new TaskCallback<Boolean>() {

			@Override
			public void onTaskError(Exception e) {
				System.err.println(e.getMessage());
				txtStatus.setText("Disconnected");
			}

			@Override
			public void onTaskCompleted(Boolean result) {
				if (result) {
					REAITConfig conf = REAITHelper.getInstance().getClient().getConfig();
					txtAPIKey.setText(conf.getApiKey());
					txtStatus.setText("Connected");
				}

			}
		};

		this.uploadBinaryCallback = new TaskCallback<String>() {

			@Override
			public void onTaskError(Exception e) {
				Msg.showError(this, null, "Upload Binary Error", e.getMessage());
			}

			@Override
			public void onTaskCompleted(String result) {
				Msg.showInfo(this, null, "Binary Upload Complete", "Successfull upload binary with hash: " + result);
				refreshStatus();
			}
		};

		this.deleteBinaryCallback = new TaskCallback<String>() {

			@Override
			public void onTaskError(Exception e) {
				Msg.showError(this, null, "Delete Binary Error", e.getMessage());
			}

			@Override
			public void onTaskCompleted(String result) {
				Msg.showInfo(this, null, "Binary Delete Complete", result);
				refreshStatus();
			}
		};

		this.getAnalysesCallback = new TaskCallback<JSONArray>() {

			@Override
			public void onTaskError(Exception e) {
				Msg.showError(this, null, "Get Analyses Error", e.getMessage());

			}

			@Override
			public void onTaskCompleted(JSONArray result) {
				analysisTableModel.clearData();
				for (int i = 0; i < result.length(); i++) {
					JSONObject rowStatus = result.getJSONObject(i);
					String[] row = new String[] { rowStatus.getString("creation"), rowStatus.getString("model_name"),
							rowStatus.getString("sha_256_hash"), rowStatus.getString("status") };
					analysisTableModel.addRow(row);
				}

			}
		};

		this.getBinaryEmbeddingsCallback = new TaskCallback<JSONArray>() {

			@Override
			public void onTaskError(Exception e) {
				Msg.showError(this, null, "Get Binary Embeddings Error", e.getMessage());
			}

			@Override
			public void onTaskCompleted(JSONArray result) {
				Msg.showInfo(this, null, "Got Embeddings", "Successfull got embeddings: ");

			}
		};
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		add(tabbedPane);

		JPanel analysisPanel = new JPanel();
		tabbedPane.addTab("Analysis", null, analysisPanel, null);
		analysisPanel.setLayout(new BorderLayout(0, 0));

		JPanel informationPanel = new JPanel();
		analysisPanel.add(informationPanel, BorderLayout.NORTH);

		JLabel lblAPIKey = new JLabel("RevEng.AI API Key:");
		informationPanel.add(lblAPIKey);

		txtAPIKey = new JTextField();
		lblAPIKey.setLabelFor(txtAPIKey);
		txtAPIKey.setToolTipText("API key for connecting to RevEng.AI");
		txtAPIKey.setHorizontalAlignment(SwingConstants.CENTER);
		txtAPIKey.setText("Not Configured");
		txtAPIKey.setEditable(false);
		informationPanel.add(txtAPIKey);
		txtAPIKey.setColumns(26);

		JPanel analysisActionsPanel = new JPanel();
		analysisPanel.add(analysisActionsPanel, BorderLayout.WEST);
		analysisActionsPanel.setLayout(new BoxLayout(analysisActionsPanel, BoxLayout.Y_AXIS));

		JButton btnUpload = new JButton("Upload");
		btnUpload.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				Task task = new UploadCurrentBinaryTask(uploadBinaryCallback);
				TaskLauncher.launch(task);
			}
		});
		analysisActionsPanel.add(btnUpload);

		JButton btnRemove = new JButton("Remove");
		btnRemove.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				tableCursor = analysisTable.getSelectedRow();

				if (tableCursor != -1) {
					String selectedHash = (String) analysisTable.getValueAt(tableCursor, 2);
					Task task = new DeleteBinaryTask(deleteBinaryCallback, selectedHash);
					TaskLauncher.launch(task);
				}
			}
		});

		JButton btnGetBinaryEmbeddings = new JButton("Get All");
		btnGetBinaryEmbeddings.setEnabled(false);
		btnGetBinaryEmbeddings.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				tableCursor = analysisTable.getSelectedRow();

				if (tableCursor != -1) {
					String selectedHash = (String) analysisTable.getValueAt(tableCursor, 2);
					String selectedModel = (String) analysisTable.getValueAt(tableCursor, 1);
					Task task = new GetBinaryEmbeddingsTask(getBinaryEmbeddingsCallback, selectedHash, selectedModel);
					TaskLauncher.launch(task);
				}
			}
		});
		
		JButton btnUseAnalysis = new JButton("Use");
		btnUseAnalysis.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				tableCursor = analysisTable.getSelectedRow();

				if (tableCursor != -1) {
					String selectedHash = (String) analysisTable.getValueAt(tableCursor, 2);
					REAITHelper.getInstance().getClient().getConfig().setAnalysisHash(selectedHash);
					Msg.showInfo(this, null, "Binary Embeddings", "Using Embeddings from " + selectedHash);
				}
			}
		});
		btnUseAnalysis.setToolTipText("Use the selected analysis result and model for function embeddings");
		analysisActionsPanel.add(btnUseAnalysis);
		btnGetBinaryEmbeddings.setToolTipText("Get all embeddings for the current binary from the selected model");
		analysisActionsPanel.add(btnGetBinaryEmbeddings);
		analysisActionsPanel.add(btnRemove);

		JSeparator separator = new JSeparator();
		analysisActionsPanel.add(separator);

		JButton btnRefresh = new JButton("Refresh");
		analysisActionsPanel.add(btnRefresh);

		JPanel analysisTablePanel = new JPanel();
		analysisPanel.add(analysisTablePanel, BorderLayout.CENTER);
		analysisTable = new JTable(analysisTableModel);
		JScrollPane scrollPane = new JScrollPane(analysisTable);
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		analysisTablePanel.add(scrollPane);

		JPanel actionPanel = new JPanel();
		analysisPanel.add(actionPanel, BorderLayout.SOUTH);
		actionPanel.setLayout(new BorderLayout(0, 0));

		JPanel statusPanel = new JPanel();
		actionPanel.add(statusPanel, BorderLayout.WEST);

		JLabel lblStatus = new JLabel("Status:");
		statusPanel.add(lblStatus);
		lblStatus.setAlignmentX(Component.CENTER_ALIGNMENT);

		txtStatus = new JTextField();
		lblStatus.setLabelFor(txtStatus);
		statusPanel.add(txtStatus);
		txtStatus.setHorizontalAlignment(SwingConstants.CENTER);
		txtStatus.setToolTipText("Status of connection to RevEng.AI Server");
		txtStatus.setText("Disconnected");
		txtStatus.setEditable(false);
		txtStatus.setColumns(8);
		
		JPanel listingActionsPanel = new JPanel();
		actionPanel.add(listingActionsPanel, BorderLayout.CENTER);
		
		JButton btnAutoAnalyse = new JButton("Auto Analyse");
		btnAutoAnalyse.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				AutoAnalyseDockableDialog autoAnalyse = new AutoAnalyseDockableDialog();
				plugin.showDialog(autoAnalyse);
			}
		});
		listingActionsPanel.add(btnAutoAnalyse);
		
				JPanel buttonsPanel = new JPanel();
				actionPanel.add(buttonsPanel, BorderLayout.EAST);
				
						JButton btnEditConfig = new JButton("Edit Configuration");
						btnEditConfig.addMouseListener(new MouseAdapter() {
							@Override
							public void mouseClicked(MouseEvent e) {
								ConfigureDockableDialog configure = new ConfigureDockableDialog();
								plugin.showDialog(configure);
							}
						});
						buttonsPanel.add(btnEditConfig);
						btnEditConfig.setAlignmentX(Component.RIGHT_ALIGNMENT);

		JPanel CollectionsPanel = new JPanel();
		tabbedPane.addTab("Collections", null, CollectionsPanel, null);
		tabbedPane.setEnabledAt(1, false);
		CollectionsPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel collectionActionsPanel = new JPanel();
		CollectionsPanel.add(collectionActionsPanel, BorderLayout.WEST);
		
		JButton btnGetCollections = new JButton("Get Collections");
		btnGetCollections.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				
			}
		});
		btnGetCollections.setToolTipText("Get the list of available collections for comparision");
		collectionActionsPanel.add(btnGetCollections);
		
		JPanel collectionsTablePanel = new JPanel();
		CollectionsPanel.add(collectionsTablePanel, BorderLayout.CENTER);
		
		JScrollPane collectionsTableScrollPane = new JScrollPane();
		collectionsTableScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		collectionsTablePanel.add(collectionsTableScrollPane);
		
		collectionsTable = new JTable(collectionsTableModel);
		collectionsTableScrollPane.setViewportView(collectionsTable);
		btnRefresh.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				refreshConfig();
			}
		});

		refreshConfig();
	}

	private void refreshStatus() {
		Task statusTask = new GetAnalysesStatusTask(getAnalysesCallback);
		TaskLauncher.launch(statusTask);
	}

	private void refreshConfig() {
		Task configTask = new ReadConfigFileTask(readConfigFileCallback);
		TaskLauncher.launch(configTask);
		refreshStatus();
	}

	public void setAPIKey(String apiKey) {
		txtAPIKey.setText(apiKey);
	}

	public void setStatus(String status) {
		txtStatus.setText(status);
	}

}
