package ai.reveng.reait.ghidra.component;

import javax.swing.JComponent;

import ai.reveng.reait.ghidra.component.panel.ConfigurationPanel;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.Msg;
import resources.Icons;

public class ConfigureComponentProvider extends ComponentProvider {
	private ConfigurationPanel panel;
	private DockingAction action;

	public ConfigureComponentProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		buildPanel();
		createActions();
	}

	// Customize GUI
	private void buildPanel() {
		panel = new ConfigurationPanel();
		setVisible(true);
	}

	// TODO: Customize actions
	private void createActions() {
		action = new DockingAction("My Action", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
