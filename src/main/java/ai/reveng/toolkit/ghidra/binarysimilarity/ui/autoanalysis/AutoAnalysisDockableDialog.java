package ai.reveng.toolkit.ghidra.binarysimilarity.ui.autoanalysis;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.autoanalysis.panels.AutoAnalysisPanel;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

/**
 * Provides a GUI for selecting the confidence threshold for auto renaming of functions
 */
public class AutoAnalysisDockableDialog extends ComponentProviderAdapter {
	private AutoAnalysisPanel panel;

	public AutoAnalysisDockableDialog(PluginTool tool) {
		super(tool, ReaiPluginPackage.WINDOW_PREFIX+"Auto Analysis", ReaiPluginPackage.NAME);
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
