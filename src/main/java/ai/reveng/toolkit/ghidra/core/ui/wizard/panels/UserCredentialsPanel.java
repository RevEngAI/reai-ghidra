package ai.reveng.toolkit.ghidra.core.ui.wizard.panels;

import java.awt.Component;

import javax.swing.JComponent;
import javax.swing.JPanel;

import ai.reveng.toolkit.ghidra.core.services.configuration.ConfigurationData;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.wizard.AbstractMageJPanel;
import docking.wizard.AbstractWizardJPanel;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.MagePanel;
import docking.wizard.WizardPanel;
import docking.wizard.WizardPanelDisplayability;
import docking.wizard.WizardPanelListener;
import docking.wizard.WizardState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.BoxLayout;
import javax.swing.JTextField;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;

public class UserCredentialsPanel extends AbstractMageJPanel<SetupWizardStateKey> {
	private PluginTool tool;
	private JTextField tfApiKey;
	private JTextField tfHostname;
	
	public UserCredentialsPanel(PluginTool tool) {
		this.tool = tool;
		setLayout(new BorderLayout(0, 0));
		
		JPanel infoPanel = new JPanel();
		add(infoPanel, BorderLayout.NORTH);
		
		JLabel lblTitle = new JLabel("Setup Account Information");
		infoPanel.add(lblTitle);
		
		JPanel userDetailsPanel = new JPanel();
		add(userDetailsPanel, BorderLayout.CENTER);
		userDetailsPanel.setLayout(new BoxLayout(userDetailsPanel, BoxLayout.Y_AXIS));
		
		JPanel apiKeyPanel = new JPanel();
		userDetailsPanel.add(apiKeyPanel);
		
		JLabel lblApiKey = new JLabel("API Key:");
		apiKeyPanel.add(lblApiKey);
		
		tfApiKey = new JTextField();
		tfApiKey.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent e) {
				notifyListenersOfValidityChanged();
			}
		});
		tfApiKey.setToolTipText("API key from your account settings");
		apiKeyPanel.add(tfApiKey);
		tfApiKey.setColumns(10);
		
		JPanel hostnamePanel = new JPanel();
		userDetailsPanel.add(hostnamePanel);
		
		JLabel lblHostname = new JLabel("Hostname:");
		hostnamePanel.add(lblHostname);
		
		tfHostname = new JTextField();
		tfHostname.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent e) {
				notifyListenersOfValidityChanged();
			}
		});
		tfHostname.setToolTipText("URL hosting the RevEng.ai Server");
		tfHostname.setText("https://api.reveng.ai");
		hostnamePanel.add(tfHostname);
		tfHostname.setColumns(10);
	}

	@Override
	public void addDependencies(WizardState<SetupWizardStateKey> state) {
		// none
		return;
		
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(WizardState<SetupWizardStateKey> state) {
		return WizardPanelDisplayability.MUST_BE_DISPLAYED;
	}

	@Override
	public void enterPanel(WizardState<SetupWizardStateKey> state) throws IllegalPanelStateException {
		// nothing todo atm
		
	}

	@Override
	public void leavePanel(WizardState<SetupWizardStateKey> state) {
		updateStateObjectWithPanelInfo(state);
		
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<SetupWizardStateKey> state) {
		state.put(SetupWizardStateKey.API_KEY, tfApiKey.getText());
		state.put(SetupWizardStateKey.HOSTNAME, tfHostname.getText());
		
	}

	@Override
	public void dispose() {
		// nothing for now
		
	}

	@Override
	public String getTitle() {
		return "RevEng.AI Credentials";
	}

	@Override
	public boolean isValidInformation() {
		// check each of the provided fields
		if (tfApiKey.getText().isEmpty()) {
			notifyListenersOfStatusMessage("Please provide your API key");
			return false;
		}
		if (tfHostname.getText().isEmpty()) {
			notifyListenersOfStatusMessage("Please enter a hostname for you API server");
			return false;
		}
		
		notifyListenersOfStatusMessage(" ");
		return true;
	}

	@Override
	public void initialize() {
		// TODO Auto-generated method stub
		
	}
}
