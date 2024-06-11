package ai.reveng.toolkit.ghidra.core.ui.wizard.panels;

import ai.reveng.toolkit.ghidra.core.services.api.*;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.wizard.AbstractMageJPanel;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.WizardPanelDisplayability;
import docking.wizard.WizardState;
import java.awt.BorderLayout;
import javax.swing.JPanel;

import org.json.JSONArray;

import javax.swing.JLabel;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.util.List;

public class UserAvailableModelsPanel extends AbstractMageJPanel<SetupWizardStateKey> {
	private static final long serialVersionUID = 1601622079507022654L;
	private JComboBox<String> cbModel;

	public UserAvailableModelsPanel() {
		setLayout(new BorderLayout(0, 0));

		JPanel titlePanel = new JPanel();
		add(titlePanel, BorderLayout.NORTH);

		JLabel lblTitle = new JLabel("Set AI Model");
		titlePanel.add(lblTitle);

		JPanel modelInfoPanel = new JPanel();
		add(modelInfoPanel);
		modelInfoPanel.setLayout(new BoxLayout(modelInfoPanel, BoxLayout.Y_AXIS));

		JPanel modelSelectionPanel = new JPanel();
		modelInfoPanel.add(modelSelectionPanel);
		modelSelectionPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

		JLabel lblModel = new JLabel("Model");
		modelSelectionPanel.add(lblModel);

		cbModel = new JComboBox<String>();
		cbModel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				notifyListenersOfValidityChanged();
			}
		});
		cbModel.setEnabled(false);
		modelSelectionPanel.add(cbModel);
	}

	@Override
	public void addDependencies(WizardState<SetupWizardStateKey> state) {
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(WizardState<SetupWizardStateKey> state) {
		return WizardPanelDisplayability.MUST_BE_DISPLAYED;
	}

	@Override
	public void enterPanel(WizardState<SetupWizardStateKey> state) throws IllegalPanelStateException {
		String apiKey = state.get(SetupWizardStateKey.API_KEY).toString();
		String hostname = state.get(SetupWizardStateKey.HOSTNAME).toString();

		System.out.println("API Key: " + apiKey);
		System.out.println("Hostname: " + hostname);

		TypedApiImplementation api = new TypedApiImplementation(hostname, apiKey);
		List<ModelInfo> res = api.models();


		System.out.println(res);

		String[] modelNames = new String[res.size()];
		for (int i = 0; i < res.size(); i++) {
			modelNames[i] = res.get(i).getName();
		}
		DefaultComboBoxModel<String> cbModelNames = new DefaultComboBoxModel<String>(modelNames);
		cbModel.setModel(cbModelNames);
		cbModel.setEnabled(true);

	}

	@Override
	public void leavePanel(WizardState<SetupWizardStateKey> state) {
		updateStateObjectWithPanelInfo(state);

	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<SetupWizardStateKey> state) {
		String model = cbModel.getSelectedItem().toString();
		state.put(SetupWizardStateKey.MODEL, model);
		System.out.println("Using Model: " + model);

	}

	@Override
	public void dispose() {
	}

	@Override
	public String getTitle() {
		return "Setup Mode";
	}

	@Override
	public boolean isValidInformation() {
		if (!cbModel.isEnabled()) {
			notifyListenersOfStatusMessage("Please select a model");
			return false;
		}
		notifyListenersOfStatusMessage(" ");
		return true;
	}

	@Override
	public void initialize() {
	}
}
