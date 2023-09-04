package ai.reveng.toolkit.ghidra.core.ui.wizard.panels;

import javax.swing.JPanel;

import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.wizard.AbstractMageJPanel;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.WizardPanelDisplayability;
import docking.wizard.WizardState;
import ghidra.framework.plugintool.PluginTool;
import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.BoxLayout;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.InputMethodListener;
import java.awt.event.InputMethodEvent;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

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

		DocumentListener documentListener = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				notifyListenersOfValidityChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				notifyListenersOfValidityChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				notifyListenersOfValidityChanged();
			}
		};

		tfApiKey = new JTextField();
		tfApiKey.getDocument().addDocumentListener(documentListener);
		tfApiKey.setToolTipText("API key from your account settings");
		apiKeyPanel.add(tfApiKey);
		tfApiKey.setColumns(10);

		JPanel hostnamePanel = new JPanel();
		userDetailsPanel.add(hostnamePanel);

		JLabel lblHostname = new JLabel("Hostname:");
		hostnamePanel.add(lblHostname);

		tfHostname = new JTextField();
		tfHostname.getDocument().addDocumentListener(documentListener);
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
