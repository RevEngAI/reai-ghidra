package ai.reveng.toolkit.ghidra.component.panel;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import javax.swing.JLabel;
import javax.swing.JButton;
import javax.swing.JSlider;
import javax.swing.event.ChangeListener;

import org.json.JSONArray;
import org.json.JSONObject;

import ai.reveng.toolkit.exceptions.RE_AIApiException;
import ai.reveng.toolkit.ghidra.RE_AIPluginPackage;
import ai.reveng.toolkit.ghidra.RE_AIToolkitHelper;
import ai.reveng.toolkit.ghidra.task.GetBinaryEmbeddingsTask;
import ai.reveng.toolkit.ghidra.task.TaskCallback;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;

import javax.swing.event.ChangeEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Vector;

public class AutoAnalysePanel extends JPanel {
	private static final long serialVersionUID = -2434211840839666156L;
	
	private TaskCallback<JSONArray> getBinaryEmbeddingsCallback;
	private JSlider confidenceSlider;

	/**
	 * Create the panel.
	 */
	public AutoAnalysePanel() {
		setLayout(new BorderLayout(0, 0));
		
		JPanel titlePanel = new JPanel();
		add(titlePanel, BorderLayout.NORTH);
		
		JLabel lblTitle = new JLabel("Auto Analyse");
		titlePanel.add(lblTitle);
		
		JPanel optionsPanel = new JPanel();
		add(optionsPanel);
		optionsPanel.setLayout(new BorderLayout(0, 0));
		
		JPanel confidencePanel = new JPanel();
		optionsPanel.add(confidencePanel, BorderLayout.SOUTH);
		confidencePanel.setLayout(new BorderLayout(0, 0));
		
		JPanel valuePanel = new JPanel();
		confidencePanel.add(valuePanel, BorderLayout.NORTH);
		
		JLabel lblConfidence = new JLabel("Confidence:");
		valuePanel.add(lblConfidence);
		
		JLabel lblConfidenceValue = new JLabel("\n");
		valuePanel.add(lblConfidenceValue);
		
		confidenceSlider = new JSlider();
		confidenceSlider.setMajorTickSpacing(10);
		confidenceSlider.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				int sliderValue = confidenceSlider.getValue();
				lblConfidenceValue.setText(Integer.toString(sliderValue));
			}
		});
		confidenceSlider.setPaintLabels(true);
		confidenceSlider.setValue(80);
		confidenceSlider.setSnapToTicks(true);
		confidenceSlider.setMinorTickSpacing(5);
		confidenceSlider.setPaintTicks(true);
		confidencePanel.add(confidenceSlider);
		
		JPanel actionPanel = new JPanel();
		add(actionPanel, BorderLayout.SOUTH);
		actionPanel.setLayout(new BorderLayout(0, 0));
		
		JButton btnStartAnalysis = new JButton("Start");
		btnStartAnalysis.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// Get all of the embeddings for this binary
				String selectedHash = RE_AIToolkitHelper.getInstance().getClient().getConfig().getAnalysisHash();
				String selectedModel = RE_AIToolkitHelper.getInstance().getClient().getConfig().getModel().toString();
				Task task = new GetBinaryEmbeddingsTask(getBinaryEmbeddingsCallback, selectedHash, selectedModel);
				TaskLauncher.launch(task);
			}
		});
		actionPanel.add(btnStartAnalysis, BorderLayout.SOUTH);
		
		getBinaryEmbeddingsCallback = new TaskCallback<JSONArray>() {

			@Override
			public void onTaskError(Exception e) {
				Msg.showError(this, null, RE_AIPluginPackage.WINDOW_PREFIX+"", e.getMessage());

			}

			@Override
			public void onTaskCompleted(JSONArray result) {
				for (Function f : RE_AIToolkitHelper.getInstance().getFlatAPI().getCurrentProgram().getFunctionManager().getFunctions(true)) {
					processFunction(f, result);
				}
			}
		};
		

	}
	
	private void processFunction(Function functionUnderReview, JSONArray embeddings) {
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
					JSONArray similarFunctions = RE_AIToolkitHelper.getInstance().getClient().ann_symbols(0.2, 8, "", functionEmbeddings);
					String canidateName = "None";
					double canidateDistance = 200;
					for (int k = 0; k < similarFunctions.length(); k++) {
						JSONObject funct = similarFunctions.getJSONObject(k);
						Double distance = funct.getDouble("distance");
						if (distance >= getConfidenceSlider().getValue()/100 && distance < canidateDistance) {
							canidateDistance = distance;
							canidateName = funct.getString("name");
						}
					}
					
					System.out.println("Canidate Function Name: " + canidateName + " with distance: " + canidateDistance);
					
				} catch (RE_AIApiException e) {
					Msg.showError(this, null, RE_AIPluginPackage.WINDOW_PREFIX+"ANN Error", e.getMessage());
				}
			}
		}
	}

	protected JSlider getConfidenceSlider() {
		return confidenceSlider;
	}
}
