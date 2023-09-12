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
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;

import javax.swing.JScrollPane;

import org.json.JSONArray;
import org.json.JSONObject;

public class RenameFunctionFromSimilarFunctionsPanel extends JPanel {
	private GTable canidateFunctionsTable;
	private CanidateFunctionModel cfm = new CanidateFunctionModel();
	private Function functionUnderReview;
	
	public RenameFunctionFromSimilarFunctionsPanel(Function functionUnderReview, ApiService apiService, String currentBinaryHash) {
		this.functionUnderReview = functionUnderReview;
		
		setLayout(new BorderLayout(0, 0));
		
		JPanel actionButtonPanel = new JPanel();
		add(actionButtonPanel, BorderLayout.WEST);
		
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
