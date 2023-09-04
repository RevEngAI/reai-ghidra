package ai.reveng.toolkit.ghidra.core.ui.wizard;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ai.reveng.toolkit.ghidra.core.ui.wizard.panels.UserAvailableModelsPanel;
import ai.reveng.toolkit.ghidra.core.ui.wizard.panels.UserCredentialsPanel;
import docking.wizard.AbstractMagePanelManager;
import docking.wizard.IllegalPanelStateException;
import docking.wizard.MagePanel;
import docking.wizard.WizardState;
import ghidra.framework.plugintool.PluginTool;

public class SetupWizardManager extends AbstractMagePanelManager<SetupWizardStateKey> {
	private PluginTool tool;

	public SetupWizardManager(WizardState<SetupWizardStateKey> initialState, PluginTool tool) {
		super(initialState);
		this.tool = tool;
	}

	@Override
	protected List<MagePanel<SetupWizardStateKey>> createPanels() {
		List<MagePanel<SetupWizardStateKey>> panels = new ArrayList<MagePanel<SetupWizardStateKey>>();
		panels.add(new UserCredentialsPanel(tool));
		panels.add(new UserAvailableModelsPanel());

		return panels;
	}

	@Override
	protected void doFinish() throws IllegalPanelStateException {
		getWizardManager().completed(true);
		cleanup();

	}

	@Override
	public void cancel() {
		cleanup();
	}

	private void cleanup() {
		List<MagePanel<SetupWizardStateKey>> panels = getPanels();
		for (MagePanel<SetupWizardStateKey> magePanel : panels) {
			magePanel.dispose();
		}
	}

}
