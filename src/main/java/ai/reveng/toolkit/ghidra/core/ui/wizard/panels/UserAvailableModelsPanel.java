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
import javax.swing.JComboBox;
import java.awt.FlowLayout;

public class UserAvailableModelsPanel extends AbstractMageJPanel<SetupWizardStateKey> {
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
		
		JComboBox cbModel = new JComboBox();
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
		
	}

	@Override
	public void leavePanel(WizardState<SetupWizardStateKey> state) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<SetupWizardStateKey> state) {
		// TODO Auto-generated method stub
		
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
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public void initialize() {
		// TODO Auto-generated method stub
		
	}

}
