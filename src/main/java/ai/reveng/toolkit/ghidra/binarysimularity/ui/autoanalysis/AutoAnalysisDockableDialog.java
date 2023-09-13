package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.panels.AutoAnalysisPanel;
import docking.DialogComponentProvider;

public class AutoAnalysisDockableDialog extends DialogComponentProvider {
	private AutoAnalysisPanel panel;

	public AutoAnalysisDockableDialog() {
		super(ReaiPluginPackage.WINDOW_PREFIX+"Function Rename", true);
		buildPanel();
	}

	private void buildPanel() {
		panel = new AutoAnalysisPanel();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
