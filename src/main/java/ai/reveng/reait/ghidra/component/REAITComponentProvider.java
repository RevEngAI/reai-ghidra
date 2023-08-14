package ai.reveng.reait.ghidra.component;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;

import ai.reveng.reait.ghidra.component.panel.REAITPanel;
import docking.ComponentProvider;
import ghidra.framework.plugintool.Plugin;

public class REAITComponentProvider extends ComponentProvider {

	private JPanel panel;

	public REAITComponentProvider(Plugin plugin, String name) {
		super(plugin.getTool(), name, "RevEngAI Toolkit");
		createComponent(plugin);
	}

	private void createComponent(Plugin plugin) {
		panel = new REAITPanel(plugin.getTool());
		// try and read the config file
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
