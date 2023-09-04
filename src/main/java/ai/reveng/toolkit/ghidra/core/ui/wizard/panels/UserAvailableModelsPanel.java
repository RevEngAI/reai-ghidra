package ai.reveng.toolkit.ghidra.core.ui.wizard.panels;

import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import docking.wizard.AbstractMageJPanel;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.WizardPanelDisplayability;
import docking.wizard.WizardState;
import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JLabel;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import java.awt.FlowLayout;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class UserAvailableModelsPanel extends AbstractMageJPanel<SetupWizardStateKey> {
	private JComboBox cbModel;
	
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
		
		cbModel = new JComboBox();
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
		// TODO Auto-generated method stub
		
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(WizardState<SetupWizardStateKey> state) {
		// TODO Auto-generated method stub
		return WizardPanelDisplayability.MUST_BE_DISPLAYED;
	}

	@Override
	public void enterPanel(WizardState<SetupWizardStateKey> state) throws IllegalPanelStateException {
		// TODO Auto-generated method stub
		String[] values = {"TestModel1"};
		DefaultComboBoxModel<String> cbModelNames = new DefaultComboBoxModel<String>(values);
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
		// TODO Auto-generated method stub
		
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
		// TODO Auto-generated method stub
		
	}
}
