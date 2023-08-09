package ai.reveng.reait.ghidra.component.panel;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;

import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import ai.reveng.reait.REAITClient;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.model.ModelInfo;

import javax.swing.JSeparator;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

public class ConfigurationPanel extends JPanel {
	private JTextField tfHostname;
	private JTextField tfAPIKey;
	private JComboBox cbModelName;
	private JComboBox cbModelVersion;

	/**
	 * Create the panel.
	 */
	public ConfigurationPanel() {
		setLayout(new BorderLayout(0, 0));
		setPreferredSize(new Dimension(450, 310));
		setMaximumSize(getPreferredSize());
		setMinimumSize(getPreferredSize());
		
		JPanel configOptionsPanel = new JPanel();
		add(configOptionsPanel, BorderLayout.CENTER);
		configOptionsPanel.setLayout(new BoxLayout(configOptionsPanel, BoxLayout.Y_AXIS));
		
		JPanel hostnamePanel = new JPanel();
		configOptionsPanel.add(hostnamePanel);
		
		JLabel lblHostname = new JLabel("Hostname:");
		hostnamePanel.add(lblHostname);
		
		tfHostname = new JTextField();
		tfHostname.setEditable(false);
		tfHostname.setText("https://api.reveng.ai");
		hostnamePanel.add(tfHostname);
		tfHostname.setColumns(10);
		
		JSeparator separator = new JSeparator();
		configOptionsPanel.add(separator);
		
		JPanel apiKeyPanel = new JPanel();
		configOptionsPanel.add(apiKeyPanel);
		apiKeyPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		
		JLabel lblAPIKey = new JLabel("API Key");
		apiKeyPanel.add(lblAPIKey);
		
		tfAPIKey = new JTextField();
		tfAPIKey.setText("xxxx-xxxx-xxxx-xxxx");
		apiKeyPanel.add(tfAPIKey);
		tfAPIKey.setColumns(10);
		
		JSeparator separator_1 = new JSeparator();
		configOptionsPanel.add(separator_1);
		
		JPanel modelPanel = new JPanel();
		configOptionsPanel.add(modelPanel);
		modelPanel.setLayout(new BoxLayout(modelPanel, BoxLayout.Y_AXIS));
		
		JPanel modelPanelTitle = new JPanel();
		modelPanel.add(modelPanelTitle);
		modelPanelTitle.setLayout(new BoxLayout(modelPanelTitle, BoxLayout.X_AXIS));
		
		JLabel lblModelTitle = new JLabel("Model");
		modelPanelTitle.add(lblModelTitle);
		
		JPanel modelParamsPanel = new JPanel();
		modelPanel.add(modelParamsPanel);
		
		JLabel lblModelName = new JLabel("Name:");
		modelParamsPanel.add(lblModelName);
		
		cbModelName = new JComboBox();
		cbModelName.setEnabled(false);
		modelParamsPanel.add(cbModelName);
		
		JLabel lblModelVersion = new JLabel("Version");
		modelParamsPanel.add(lblModelVersion);
		
		cbModelVersion = new JComboBox();
		cbModelVersion.setEnabled(false);
		modelParamsPanel.add(cbModelVersion);
		
		JPanel modelUpdatesPanel = new JPanel();
		modelPanel.add(modelUpdatesPanel);
		
		JButton btnGetModels = new JButton("Check for Updates");
		btnGetModels.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				REAITHelper helper = REAITHelper.getInstance();
				helper.setClient(new REAITClient(tfAPIKey.getText(), tfHostname.getText()));
				List<ModelInfo> models = helper.getClient().getModels();
				Vector<String> modelNames = new Vector<String>();
				for (ModelInfo model : models) {
					modelNames.add(model.getName());
				}
				DefaultComboBoxModel<String> cbModelNames = new DefaultComboBoxModel<String>(modelNames);
				cbModelName.setModel(cbModelNames);
				cbModelName.setEnabled(true);
			}
		});
		modelUpdatesPanel.add(btnGetModels);
		
		JPanel actionPanel = new JPanel();
		add(actionPanel, BorderLayout.SOUTH);
		actionPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));
		
		JButton btnCancel = new JButton("Cancel");
		actionPanel.add(btnCancel);
		
		JButton btnConnect = new JButton("Connect");
		actionPanel.add(btnConnect);

	}

	public JComboBox getModelName() {
		return cbModelName;
	}
	public JComboBox getModelVersion() {
		return cbModelVersion;
	}
	public JTextField getAPIKey() {
		return tfAPIKey;
	}
	public JTextField getHostname() {
		return tfHostname;
	}
}
