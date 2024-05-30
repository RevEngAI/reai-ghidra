package ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.panels.RenameFunctionFromSimilarFunctionsPanel;
import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;

/**
 * GUI component for renaming a function from a selection of candidate functions
 */
public class FunctionSimularityDockableDialog extends DialogComponentProvider {
	private RenameFunctionFromSimilarFunctionsPanel panel;

	/**
	 * 
	 * @param func Function you would like to rename
	 * @param tool
	 */
	public FunctionSimularityDockableDialog(Function func, PluginTool tool) {
		super(ReaiPluginPackage.WINDOW_PREFIX + "Function Rename", true);

		buildPanel(func, tool);
	}

	private void buildPanel(Function func, PluginTool tool) {
		panel = new RenameFunctionFromSimilarFunctionsPanel(func, tool);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}