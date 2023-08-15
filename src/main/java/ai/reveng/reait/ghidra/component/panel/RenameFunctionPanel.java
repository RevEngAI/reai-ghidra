package ai.reveng.reait.ghidra.component.panel;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;

import org.json.JSONArray;
import org.json.JSONObject;

import ai.reveng.reait.exceptions.REAIApiException;
import ai.reveng.reait.ghidra.REAITHelper;
import ai.reveng.reait.ghidra.component.model.FunctionEmbeddingsTableModel;
import ai.reveng.reait.ghidra.task.DeleteBinaryTask;
import ai.reveng.reait.ghidra.task.GetBinaryEmbeddingsTask;
import ai.reveng.reait.ghidra.task.TaskCallback;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class RenameFunctionPanel extends JPanel {
	private static final long serialVersionUID = -2889751212741820135L;
	private JTextField tfFunctionName;
	private JTable functionEmbeddingsTable;
	
	private FunctionEmbeddingsTableModel feTableModel = new FunctionEmbeddingsTableModel();

	private TaskCallback<JSONArray> getBinaryEmbeddingsCallback;

	private JSONArray embeddings;
	private Function functionUnderReview;
	private int tableCursor;

	/**
	 * Create the panel.
	 */
	public RenameFunctionPanel(Function func) {
		functionUnderReview = func;
		setLayout(new BorderLayout(0, 0));
		setSize(620, 330);

		JPanel TitlePanel = new JPanel();
		add(TitlePanel, BorderLayout.NORTH);

		JLabel lblFunctionName = new JLabel("Function:");
		TitlePanel.add(lblFunctionName);

		tfFunctionName = new JTextField();
		tfFunctionName.setEditable(false);
		TitlePanel.add(tfFunctionName);
		tfFunctionName.setColumns(30);
		tfFunctionName.setText(func.getName());

		JPanel ActionsPanel = new JPanel();
		add(ActionsPanel, BorderLayout.WEST);
		ActionsPanel.setLayout(new BoxLayout(ActionsPanel, BoxLayout.Y_AXIS));

		JButton btnGetEmbeddings = new JButton("Get Embeddings");
		btnGetEmbeddings.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// Get all of the embeddings for this binary
				String selectedHash = REAITHelper.getInstance().getClient().getConfig().getAnalysisHash();
				String selectedModel = REAITHelper.getInstance().getClient().getConfig().getModel().toString();
				Task task = new GetBinaryEmbeddingsTask(getBinaryEmbeddingsCallback, selectedHash, selectedModel);
				TaskLauncher.launch(task);
			}
		});
		ActionsPanel.add(btnGetEmbeddings);
		
		JButton btnRename = new JButton("Rename");
		btnRename.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				tableCursor = functionEmbeddingsTable.getSelectedRow();

				if (tableCursor != -1) {
					int transactionID = REAITHelper.getInstance().getFlatAPI().getCurrentProgram().startTransaction("Rename function");
					try {
						functionUnderReview.setName((String) functionEmbeddingsTable.getValueAt(tableCursor, 0), SourceType.USER_DEFINED);
						REAITHelper.getInstance().getFlatAPI().getCurrentProgram().endTransaction(transactionID, true);
					} catch (Exception e1) {
						REAITHelper.getInstance().getFlatAPI().getCurrentProgram().endTransaction(transactionID, false);
					}
				}
			}
		});
		ActionsPanel.add(btnRename);

		JPanel EmbeddingsPanel = new JPanel();
		add(EmbeddingsPanel, BorderLayout.CENTER);

		JScrollPane functionEmbeddingsScrollPane = new JScrollPane();
		functionEmbeddingsScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		EmbeddingsPanel.add(functionEmbeddingsScrollPane);

		functionEmbeddingsTable = new JTable(feTableModel);
		functionEmbeddingsScrollPane.setViewportView(functionEmbeddingsTable);

		getBinaryEmbeddingsCallback = new TaskCallback<JSONArray>() {

			@Override
			public void onTaskError(Exception e) {
				Msg.showError(this, null, "", e.getMessage());

			}

			@Override
			public void onTaskCompleted(JSONArray result) {
				
				embeddings = result;

				// find the embedding for this function
				for (int i = 0; i < embeddings.length(); i++) {
					JSONObject embedding = embeddings.getJSONObject(i);
					if (embedding.getString("name").equals(functionUnderReview.getName())) {
						// send the request
						JSONArray functionEmbeddingsJson = new JSONArray(embedding.getJSONArray("embedding"));
						Vector<Double> functionEmbeddings = new Vector<Double>();
						for (int j = 0; j < functionEmbeddingsJson.length(); j++) {
							functionEmbeddings.add(functionEmbeddingsJson.getDouble(j));
						}
						System.out.println("Got embeddings for: " + embedding.getString("name"));
						try {
							JSONArray similarFunctions = REAITHelper.getInstance().getClient().ann_symbols(0.2, 8, "", functionEmbeddings);
							for (int k = 0; k < similarFunctions.length(); k++) {
								JSONObject funct = similarFunctions.getJSONObject(k);
								feTableModel.addRow(new String[] {funct.getString("name"), funct.get("distance").toString(), funct.getString("binary_name")});
							}
							
						} catch (REAIApiException e) {
							Msg.showError(this, null, "ANN Error", e.getMessage());
						}
					}
				}
			}
		};

	}

}
