package ai.reveng.reait.ghidra.component;

import javax.swing.JComponent;

import ai.reveng.reait.ghidra.component.panel.ConfigurationPanel;
import docking.DialogComponentProvider;

public class ConfigureDockableDialog extends DialogComponentProvider {
	private ConfigurationPanel panel;

	public ConfigureDockableDialog() {
		super("REAIT Configuration", true);
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