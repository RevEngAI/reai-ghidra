package ai.reveng.reait.ghidra.component;

import javax.swing.JComponent;

import ai.reveng.reait.ghidra.component.panel.ConfigurationPanel;
import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;

public class ConfigureComponentProvider extends ComponentProvider {
	private ConfigurationPanel panel;

	public ConfigureComponentProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		buildPanel();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new ConfigurationPanel();
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
