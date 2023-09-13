package ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.panels;

import javax.swing.JPanel;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.binarysimularity.ui.functionsimularity.models.CanidateFunctionModel;
import ai.reveng.toolkit.ghidra.core.services.api.ApiResponse;
import ai.reveng.toolkit.ghidra.core.services.api.ApiService;
import ai.reveng.toolkit.ghidra.core.services.api.types.Binary;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionEmbedding;

import java.awt.BorderLayout;

import docking.widgets.table.GTable;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import javax.swing.JScrollPane;

import org.json.JSONArray;
import org.json.JSONObject;
import javax.swing.JButton;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class RenameFunctionFromSimilarFunctionsPanel extends JPanel {
	private GTable canidateFunctionsTable;
	private CanidateFunctionModel cfm = new CanidateFunctionModel();
	private Function functionUnderReview;
	
	public RenameFunctionFromSimilarFunctionsPanel(Function functionUnderReview, PluginTool tool) {
		this.functionUnderReview = functionUnderReview;
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager.getCurrentProgram();
		ApiService apiService = tool.getService(ApiService.class);
		String currentBinaryHash = currentProgram.getExecutableSHA256();
		
		setLayout(new BorderLayout(0, 0));
		
		JPanel actionButtonPanel = new JPanel();
		add(actionButtonPanel, BorderLayout.WEST);
		
		JButton btnRename = new JButton("Rename");
		btnRename.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				
				int tableCursor = canidateFunctionsTable.getSelectedRow();
				
				if (tableCursor != -1) {
					int transactionID = currentProgram.startTransaction("Rename function from similar functions");
					try {
						functionUnderReview.setName((String) canidateFunctionsTable.getValueAt(tableCursor, 0), SourceType.USER_DEFINED);
						currentProgram.endTransaction(transactionID, true);
					} catch (DuplicateNameException exc) {
						System.err.println("Symbol already exists");
						currentProgram.endTransaction(transactionID, false);
						Msg.showError(actionButtonPanel, btnRename, ReaiPluginPackage.WINDOW_PREFIX+"Rename Function Error", exc.getMessage());
					} catch (Exception exc) {
						currentProgram.endTransaction(transactionID, false);
						System.err.println("Unknown Error");
					}
				}
			}
		});
		actionButtonPanel.add(btnRename);
		
		JScrollPane canidateFunctionsScrollPanel = new JScrollPane();
		add(canidateFunctionsScrollPanel, BorderLayout.CENTER);
		
		canidateFunctionsTable = new GTable(cfm);
		canidateFunctionsScrollPanel.setViewportView(canidateFunctionsTable);
		
		ApiResponse res = apiService.embeddings(currentBinaryHash);
		
		if (res.getStatusCode() > 299) {
			Msg.showError(actionButtonPanel, canidateFunctionsScrollPanel, ReaiPluginPackage.WINDOW_PREFIX+"Function Simularity", res.getJsonObject().get("error"));
			return;
		}
		
		Binary bin = new Binary(res.getJsonArray());
		
		FunctionEmbedding fe = bin.getFunctionEmbedding(functionUnderReview.getName());
		
		if (fe == null) {
			Msg.showError(bin, canidateFunctionsScrollPanel, ReaiPluginPackage.WINDOW_PREFIX+"Find Similar Functions", "No similar functions found");
			return;
		}
		
		res = apiService.nearestSymbols(fe.getEmbedding(), 5, null);
		
		JSONArray jCanidateFunctions = res.getJsonArray();
		
		for (int i = 0; i < jCanidateFunctions.length(); i++) {
			JSONObject jCanidateFunction = jCanidateFunctions.getJSONObject(i);
			cfm.addRow(new String[] {jCanidateFunction.getString("name"), jCanidateFunction.get("distance").toString(), jCanidateFunction.getString("binary_name")});
		}
	}

}
