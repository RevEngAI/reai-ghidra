package ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.panels;

import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.models.CanidateFunctionModel;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ai.reveng.toolkit.ghidra.core.services.logging.ReaiLoggingService;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;

import javax.swing.*;
import java.awt.*;

/**
 * GUI for displaying results from a FunctionSimilarity request
 */
public class RenameFunctionFromSimilarFunctionsPanel extends JPanel {
	private static final long serialVersionUID = -7365592104915627273L;
	private GhidraTable canidateFunctionsTable;
	private CanidateFunctionModel cfm;
    private JScrollPane canidateFunctionsScrollPanel;
	private JPanel actionButtonPanel;
	private JPanel parametersPanel;
	private JSeparator separator;
	private JLabel lblParamsPanelTitle;
	private JProgressBar progressBar;
	private JPanel progressPanel;
	private JLabel lblProgressStatusText;
	private JButton btnRefresh;
	private Program currentProgram;
	
	private ReaiLoggingService loggingService;

	public RenameFunctionFromSimilarFunctionsPanel(Function functionUnderReview, PluginTool tool) {
		
		loggingService = tool.getService(ReaiLoggingService.class);
		if (loggingService == null) {
			Msg.error(this, "Unable to access logging service");
		}
		
		ProgramManager programManager = tool.getService(ProgramManager.class);
		this.currentProgram = programManager.getCurrentProgram();
        this.cfm = new CanidateFunctionModel(tool, functionUnderReview);

		setLayout(new BorderLayout(0, 0));

		actionButtonPanel = new JPanel();
		add(actionButtonPanel, BorderLayout.WEST);
		actionButtonPanel.setLayout(new BoxLayout(actionButtonPanel, BoxLayout.Y_AXIS));

		parametersPanel = new JPanel();
		actionButtonPanel.add(parametersPanel);
		parametersPanel.setLayout(new BoxLayout(parametersPanel, BoxLayout.Y_AXIS));

		lblParamsPanelTitle = new JLabel("Symbol Options");
		lblParamsPanelTitle.setAlignmentX(Component.CENTER_ALIGNMENT);
		parametersPanel.add(lblParamsPanelTitle);

//		debugSymbolsCheckPanel = new JPanel();
//		parametersPanel.add(debugSymbolsCheckPanel);
//		debugSymbolsCheckPanel.setLayout(new BoxLayout(debugSymbolsCheckPanel, BoxLayout.Y_AXIS));
//
//		chckbxNewCheckBox = new JCheckBox("Use Debug Symbols");
//		chckbxNewCheckBox.setAlignmentX(Component.CENTER_ALIGNMENT);
//		debugSymbolsCheckPanel.add(chckbxNewCheckBox);

//		numResultsPanel = new JPanel();
//		parametersPanel.add(numResultsPanel);
//		numResultsPanel.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

//		lblNumResults = new JLabel("Results");
//		numResultsPanel.add(lblNumResults);

//		numResultsTf = new JTextField();
//		numResultsTf.setText("5");
//		lblNumResults.setLabelFor(numResultsTf);
//		numResultsPanel.add(numResultsTf);
//		numResultsTf.setColumns(3);

		btnRefresh = new JButton("Reload");
		btnRefresh.setEnabled(true);
		btnRefresh.setAlignmentX(Component.CENTER_ALIGNMENT);
		btnRefresh.addActionListener(e -> cfm.reload());

		separator = new JSeparator();
		actionButtonPanel.add(separator);

		JButton btnApply = new JButton("Apply");
		btnApply.setAlignmentX(Component.CENTER_ALIGNMENT);

		btnApply.addActionListener(e -> {

            GhidraFunctionMatchWithSignature match = cfm.getRowObject(canidateFunctionsTable.getSelectedRow());
			if (match != null) {
				Command<Program> cmd;
				if (match.signature().isPresent()){
//					throw new UnsupportedOperationException("Not implemented yet");
					FunctionSignature signature = GhidraRevengService.getFunctionSignature(match.signature().get());
					cmd = new ApplyFunctionSignatureCmd(functionUnderReview.getEntryPoint(), signature, SourceType.USER_DEFINED);
				} else {
					cmd = new RenameLabelCmd(functionUnderReview.getSymbol(), match.functionMatch().name(), SourceType.USER_DEFINED);
				}
				currentProgram.withTransaction("Apply Similar Function Information", () -> cmd.applyTo(currentProgram));

			}
		});

//		JButton btnAnalyseSignature = new JButton("Analyse Signature");
//		btnAnalyseSignature.addActionListener( e -> {
//			var match = canidateFunctionsTable.getSelectedRowObject();
//			tool.getService(GhidraRevengService.class).sign(match.functionMatch().nearest_neighbor_id());
//		});


		progressPanel = new JPanel();
		actionButtonPanel.add(progressPanel);
		progressPanel.setLayout(new BoxLayout(progressPanel, BoxLayout.Y_AXIS));

		progressBar = new JProgressBar();
		progressPanel.add(progressBar);

//		lblProgressStatusText = new JLabel("Waiting to Fetch");
//		lblProgressStatusText.setAlignmentX(Component.CENTER_ALIGNMENT);
//		lblProgressStatusText.setHorizontalAlignment(SwingConstants.CENTER);
//		progressPanel.add(lblProgressStatusText);

		JSeparator separator_1 = new JSeparator();
		actionButtonPanel.add(separator_1);
		actionButtonPanel.add(btnApply);
		actionButtonPanel.add(btnRefresh);

		canidateFunctionsScrollPanel = new JScrollPane();
		add(canidateFunctionsScrollPanel, BorderLayout.CENTER);

		canidateFunctionsTable = new GhidraTable(cfm);
		canidateFunctionsScrollPanel.setViewportView(canidateFunctionsTable);
		canidateFunctionsTable.setActionsEnabled(true);
//		canidateFunctionsTable.addLocalAction();
//		tool.addLocalAction(this, null);

	}
}
