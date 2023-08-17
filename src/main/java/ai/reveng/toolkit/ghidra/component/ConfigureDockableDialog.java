package ai.reveng.toolkit.ghidra.component;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.component.panel.ConfigurationPanel;
import docking.DialogComponentProvider;

public class ConfigureDockableDialog extends DialogComponentProvider {
	private ConfigurationPanel panel;

	public ConfigureDockableDialog() {
		super(RE_AIPluginPackage.WINDOW_PREFIX+"REAIT Configuration", true);
		buildPanel();
	}

	private void buildPanel() {
		panel = new ConfigurationPanel();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
