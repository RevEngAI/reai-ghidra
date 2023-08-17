package ai.reveng.toolkit.ghidra.component;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.component.panel.AutoAnalysePanel;
import docking.DialogComponentProvider;

public class AutoAnalyseDockableDialog extends DialogComponentProvider {
	private AutoAnalysePanel panel;

	public AutoAnalyseDockableDialog() {
		super(RE_AIPluginPackage.WINDOW_PREFIX+"REAIT Function Rename", true);
		buildPanel();
	}

	private void buildPanel() {
		panel = new AutoAnalysePanel();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}

