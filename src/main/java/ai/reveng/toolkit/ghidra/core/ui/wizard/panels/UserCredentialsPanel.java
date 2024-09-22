package ai.reveng.toolkit.ghidra.core.ui.wizard.panels;

import javax.swing.*;

import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.InvalidAPIInfoException;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.wizard.AbstractMageJPanel;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.WizardPanelDisplayability;
import docking.wizard.WizardState;
import ghidra.framework.plugintool.PluginTool;
import java.awt.BorderLayout;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class UserCredentialsPanel extends AbstractMageJPanel<SetupWizardStateKey> {
	private static final long serialVersionUID = -9045013459967405703L;
	private JTextField tfApiKey;
	private JTextField tfHostname;
	private Boolean credentialsValidated = false;

	public UserCredentialsPanel(PluginTool tool) {
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
				credentialsValidated = false;
				notifyListenersOfValidityChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				credentialsValidated = false;
				notifyListenersOfValidityChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				credentialsValidated = false;
				notifyListenersOfValidityChanged();
			}
		};

		tfApiKey = new JTextField();
		tfApiKey.getDocument().addDocumentListener(documentListener);
		tfApiKey.setToolTipText("API key from your account settings");
		apiKeyPanel.add(tfApiKey);
		tfApiKey.setColumns(20);

		JPanel hostnamePanel = new JPanel();
		userDetailsPanel.add(hostnamePanel);

		JLabel lblHostname = new JLabel("Hostname:");
		hostnamePanel.add(lblHostname);

		tfHostname = new JTextField();
		tfHostname.getDocument().addDocumentListener(documentListener);
		tfHostname.setToolTipText("URL hosting the RevEng.AI Server");
		tfHostname.setText("https://api.reveng.ai");
		hostnamePanel.add(tfHostname);
		tfHostname.setColumns(20);

		JButton runTestsButton = new JButton("Validate Credentials");
		runTestsButton.addActionListener(e -> {
			var apiInfo = new ApiInfo(tfHostname.getText(), tfApiKey.getText());
			try {
				apiInfo.checkCredentials();
				credentialsValidated = true;
				// TODO: Get the user for this key once the API exists
				notifyListenersOfValidityChanged();

			} catch (InvalidAPIInfoException ex) {
				credentialsValidated = false;
				notifyListenersOfStatusMessage("Problem with user info:\n" + ex.getMessage());
			}

		});
		userDetailsPanel.add(runTestsButton);


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
		if (!credentialsValidated){
			notifyListenersOfStatusMessage("Please validate your credentials");
			return false;
		}
		notifyListenersOfStatusMessage("Credentials are valid");
		return true;
	}

	@Override
	public void initialize() {
	}
}
