package ai.reveng.toolkit.ghidra.core.ui.wizard;

import java.util.ArrayList;
import java.util.List;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
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
		tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_APIKEY,
				(String) getState().get(SetupWizardStateKey.API_KEY));
		tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_HOSTNAME,
				(String) getState().get(SetupWizardStateKey.HOSTNAME));
		tool.getOptions("Preferences").setString(ReaiPluginPackage.OPTION_KEY_MODEL,
				(String) getState().get(SetupWizardStateKey.MODEL));
		cleanup();

		// TODO write config to file

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
