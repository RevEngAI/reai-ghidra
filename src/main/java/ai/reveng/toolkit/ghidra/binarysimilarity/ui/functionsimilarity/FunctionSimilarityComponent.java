package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionsimilarity;

import javax.swing.*;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.settingsdialog.ANNSettingsDialog;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import generic.theme.GIcon;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.GhidraTable;

import java.awt.*;

/**
 * GUI component for renaming a function from a selection of candidate functions
 */
public class FunctionSimilarityComponent extends ComponentProviderAdapter {
	private final CanidateFunctionModel cfm;
	private final JPanel panel;
	private GhidraTable canidateFunctionsTable;
	private Icon REVENG_ICON = ReaiPluginPackage.REVENG_16;
	private Icon SEARCH_ICON = new GIcon("icon.search");
	private ToggleDockingAction includeSignaturesAction;
	private ToggleDockingAction limitToDebugSymbolsAction;
	private ToggleDockingAction companionModeAction;

	/**
	 * 
	 * @param tool
	 */
	public FunctionSimilarityComponent(PluginTool tool) {
//		super(ReaiPluginPackage.WINDOW_PREFIX + "Function Rename", true);
		super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Function Rename", ReaiPluginPackage.NAME);
		setIcon(ReaiPluginPackage.REVENG_16);
		createActions();
		this.cfm = new CanidateFunctionModel(tool);
		panel = buildPanel(tool);
	}

	private void createActions() {
		new ActionBuilder("Apply Match", getOwner())
				.popupMenuPath("Apply Match")
				.popupMenuIcon(REVENG_ICON)
//				.toolBarIcon(EDIT_ICON)
				.enabledWhen(ac -> canidateFunctionsTable.getSelectedRowCount() == 1)
				.onAction(ac -> applyMatch())
				.buildAndInstallLocal(this);

		limitToDebugSymbolsAction = new ToggleActionBuilder("Limit Search to Debug Symbols", getOwner())
				.toolBarIcon(SEARCH_ICON)
				.onAction(ac ->
						cfm.setLimitToDebugSymbols(limitToDebugSymbolsAction.isSelected())
				)
				.buildAndInstallLocal(this);

		includeSignaturesAction = new ToggleActionBuilder("Include Signatures", getOwner())
				.toolBarIcon(SEARCH_ICON)
				.description("Only show matches with signatures available")
				.onAction(ac -> {
					cfm.setLimitToSignaturesAvailable(includeSignaturesAction.isSelected());
				})
				.buildAndInstallLocal(this);

		companionModeAction = new ToggleActionBuilder("Companion Mode", getOwner())
				.toolBarIcon(REVENG_ICON)
				.description("Automatically search for matches when location changes")
				.onAction(ac -> {})
				.buildAndInstallLocal(this);

		var settingsAction = new ActionBuilder("Settings", getOwner())
				.toolBarIcon("conf.png")
				.description("Configure the search settings")
				.onAction(ac -> {
					ANNSettingsDialog dialog = new ANNSettingsDialog();
					tool.showDialog(dialog, this);
					cfm.setNumResults(dialog.getNumResults());
					cfm.setSimilarity(dialog.getSimilarity());
					this.cfm.reload();
				})
				.buildAndInstallLocal(this);


	}

	private void applyMatch(){
		GhidraFunctionMatchWithSignature match = cfm.getRowObject(canidateFunctionsTable.getSelectedRow());
		if (match != null) {
			Command cmd;
			var program = match.function().getProgram();
			if (match.signature().isPresent()){
				FunctionSignature signature = GhidraRevengService.getFunctionSignature(match.signature().get());
				cmd = new ApplyFunctionSignatureCmd(match.function().getEntryPoint(), signature, SourceType.USER_DEFINED);
			} else {
				cmd = new RenameLabelCmd(match.function().getSymbol(), match.functionMatch().name(), SourceType.USER_DEFINED);
			}
			program.withTransaction("Apply Similar Function Information", () -> cmd.applyTo(program));

		}
	}
	private JPanel buildPanel(PluginTool tool) {
		var panel = new JPanel();
		panel.setLayout(new BorderLayout(0, 0));

		var canidateFunctionsScrollPanel = new JScrollPane();
		panel.add(canidateFunctionsScrollPanel, BorderLayout.CENTER);

		canidateFunctionsTable = new GhidraTable(cfm);
		canidateFunctionsScrollPanel.setViewportView(canidateFunctionsTable);
		canidateFunctionsTable.setActionsEnabled(true);
		return panel;
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	public void triggerSearchForFunction(Function function) {
		cfm.setFunctionUnderReview(function);
	}

	public void locationChanged(ProgramLocation loc) {
		if (companionModeAction.isSelected()){
			// TODO: We might want to maintain some cache here to avoid fetching the same function multiple times
			Function function = null;
			if (loc != null){
				function = loc.getProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
			}
			triggerSearchForFunction(function);
		}
	}
}