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
import ai.reveng.reait.ghidra.task.ReadConfigFileTask;
import ai.reveng.reait.ghidra.task.TaskCallback;
import ai.reveng.reait.ghidra.task.WriteConfigFileTask;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class REAITPanel extends JPanel {
	private static final long serialVersionUID = -9128086339205968930L;
	private JTextField txtAPIKey;
	private JTextField txtStatus;
	private PluginTool plugin;
	
	private TaskCallback<Boolean> readConfigFileCallback;

	/**
	 * Create the panel.
	 */
	public REAITPanel(PluginTool plugin) {
		this.plugin = plugin;
		setLayout(new BorderLayout(0, 0));
		
		setPreferredSize(new Dimension(640, 150));
		
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
		
		JButton btnUpload = new JButton("Upload");
		analysisActionsPanel.add(btnUpload);
		
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
				txtStatus.setText("Configure Ghidra");
			}
			
			@Override
			public void onTaskCompleted(Boolean result) {
				if (result) {
					REAITConfig conf = REAITHelper.getInstance().getClient().getConfig();
					txtAPIKey.setText(conf.getApiKey());
				}
				
			}
		};
		
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
