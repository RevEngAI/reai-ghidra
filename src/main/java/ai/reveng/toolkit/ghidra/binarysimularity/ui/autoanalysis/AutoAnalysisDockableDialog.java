package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.panels.AutoAnalysisPanel;
import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;

/**
 * Provides a GUI for selecting the confidence threshold for auto renaming of functions
 */
public class AutoAnalysisDockableDialog extends DialogComponentProvider {
	private AutoAnalysisPanel panel;

	public AutoAnalysisDockableDialog(PluginTool tool) {
		super(ReaiPluginPackage.WINDOW_PREFIX+"Function Rename", true);
		buildPanel(tool);
	}

	private void buildPanel(PluginTool tool) {
		panel = new AutoAnalysisPanel(tool);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
