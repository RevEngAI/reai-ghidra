package ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.panels.RenameFunctionFromSimilarFunctionsPanel;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import docking.DialogComponentProvider;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class FunctionSimularityDockableDialog extends DialogComponentProvider {
	private RenameFunctionFromSimilarFunctionsPanel panel;

	public FunctionSimularityDockableDialog(Function func, PluginTool tool) {
		super(ReaiPluginPackage.WINDOW_PREFIX+"Function Rename", true);
		
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