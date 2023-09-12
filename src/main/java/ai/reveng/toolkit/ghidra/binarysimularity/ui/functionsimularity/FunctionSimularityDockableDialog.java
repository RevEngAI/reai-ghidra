package ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.panels.RenameFunctionFromSimilarFunctionsPanel;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class FunctionSimularityDockableDialog extends DialogComponentProvider {
	private RenameFunctionFromSimilarFunctionsPanel panel;

	public FunctionSimularityDockableDialog(Function func, ApiService apiService, Program currentProgram) {
		super(ReaiPluginPackage.WINDOW_PREFIX+"Function Rename", true);
		buildPanel(func, apiService, currentProgram);
	}

	private void buildPanel(Function func, ApiService apiService, Program currentProgram) {
		panel = new RenameFunctionFromSimilarFunctionsPanel(func, apiService, currentProgram.getExecutableSHA256());
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}