package ai.reveng.reait.ghidra.component;

import javax.swing.JComponent;

import ai.reveng.reait.ghidra.component.panel.AutoAnalysePanel;
import docking.DialogComponentProvider;

public class AutoAnalyseDockableDialog extends DialogComponentProvider {
	private AutoAnalysePanel panel;

	public AutoAnalyseDockableDialog() {
		super("REAIT Function Rename", true);
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

