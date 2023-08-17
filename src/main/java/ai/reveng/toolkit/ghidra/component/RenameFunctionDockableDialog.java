package ai.reveng.toolkit.ghidra.component;

import javax.swing.JComponent;

import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.component.panel.RenameFunctionPanel;
import docking.DialogComponentProvider;
import ghidra.program.model.listing.Function;

public class RenameFunctionDockableDialog extends DialogComponentProvider {
	private RenameFunctionPanel panel;
	private Function func;

	public RenameFunctionDockableDialog(Function func) {
		super(RE_AIPluginPackage.WINDOW_PREFIX+"Function Rename", true);
		this.func = func;
		buildPanel();
	}

	private void buildPanel() {
		panel = new RenameFunctionPanel(func);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
