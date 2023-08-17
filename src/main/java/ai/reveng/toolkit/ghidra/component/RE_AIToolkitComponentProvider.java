package ai.reveng.toolkit.ghidra.component;

import javax.swing.JComponent;
import javax.swing.JPanel;

import ai.reveng.toolkit.ghidra.component.panel.RE_AIToolkitPanel;
import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;

public class RE_AIToolkitComponentProvider extends ComponentProvider {

	private JPanel panel;

	public RE_AIToolkitComponentProvider(Plugin plugin, String name) {
		super(plugin.getTool(), name, "RevEngAI Toolkit");
		createComponent(plugin);
	}

	private void createComponent(Plugin plugin) {
		panel = new RE_AIToolkitPanel(plugin.getTool());
		// try and read the config file
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
