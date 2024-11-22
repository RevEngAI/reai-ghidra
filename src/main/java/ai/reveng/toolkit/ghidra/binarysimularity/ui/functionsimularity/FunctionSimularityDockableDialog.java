package ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.panels.RenameFunctionFromSimilarFunctionsPanel;
import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;

/**
 * GUI component for renaming a function from a selection of candidate functions
 */
public class FunctionSimularityDockableDialog extends ComponentProviderAdapter {
	private RenameFunctionFromSimilarFunctionsPanel panel;

	/**
	 * 
	 * @param func Function you would like to rename
	 * @param tool
	 */
	public FunctionSimularityDockableDialog(Function func, PluginTool tool) {
		super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Function Rename", ReaiPluginPackage.NAME);

		buildPanel(func, tool);
		tool.addLocalAction(this, new DockingAction("Test action", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				return;
			}
		});
	}

	private void buildPanel(Function func, PluginTool tool) {
		panel = new RenameFunctionFromSimilarFunctionsPanel(func, tool);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}