package ai.reveng.reait.ghidra.component.panel;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import ai.reveng.reait.REAITConfig;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.ghidra.component.ConfigureDockableDialog;
import ai.reveng.reait.ghidra.component.model.AnalysisStatusTableModel;
import ai.reveng.reait.ghidra.task.DeleteBinaryTask;
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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import javax.swing.BoxLayout;
import javax.swing.JSeparator;
import javax.swing.JTable;
import javax.swing.JScrollPane;

public class REAITPanel extends JPanel {
	private static final long serialVersionUID = -9128086339205968930L;
	private JTextField txtAPIKey;
	private JTextField txtStatus;
	private PluginTool plugin;
	
	private TaskCallback<Boolean> readConfigFileCallback;
	private TaskCallback<String> uploadBinaryCallback;
	private TaskCallback<String> deleteBinaryCallback;
	
	private int tableCursor;
	
	private JTable analysisTable;

	/**
	 * Create the panel.
	 */
	public REAITPanel(PluginTool plugin) {
		this.plugin = plugin;
		setLayout(new BorderLayout(0, 0));
		
		setPreferredSize(new Dimension(640, 230));
		
		JPanel informationPanel = new JPanel();
		add(informationPanel, BorderLayout.NORTH);
		
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
		add(analysisActionsPanel, BorderLayout.WEST);
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
		analysisActionsPanel.add(btnRemove);
		
		JSeparator separator = new JSeparator();
		analysisActionsPanel.add(separator);
		
		JButton btnRefresh = new JButton("Refresh");
		analysisActionsPanel.add(btnRefresh);
		btnRefresh.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				refreshConfig();
			}
		});
		
		JPanel analysisPanel = new JPanel();
		add(analysisPanel, BorderLayout.CENTER);
		
		AnalysisStatusTableModel model = new AnalysisStatusTableModel();
		analysisTable = new JTable(model);
		JScrollPane scrollPane = new JScrollPane(analysisTable);
		analysisPanel.add(scrollPane);
		
		JPanel actionPanel = new JPanel();
		add(actionPanel, BorderLayout.SOUTH);
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
				LocalDateTime currentDateTime = LocalDateTime.now();
				DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
				model.addRow(new String[] {currentDateTime.format(formatter), REAITHelper.getInstance().getClient().getConfig().getModel().toString(), result, "In-Progress"});
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
				model.deleteRow(tableCursor);
			}
		};
		
		refreshConfig();
	}
	
	private void refreshConfig() {
		Task task = new ReadConfigFileTask(readConfigFileCallback);
		TaskLauncher.launch(task);
	}
	
	public void setAPIKey(String apiKey) {
		txtAPIKey.setText(apiKey);
	}
	
	public void setStatus(String status) {
		txtStatus.setText(status);
	}

}
