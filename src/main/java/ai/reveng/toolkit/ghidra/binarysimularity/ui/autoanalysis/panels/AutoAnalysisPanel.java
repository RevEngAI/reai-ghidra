package ai.reveng.toolkit.ghidra.binarysimularity.ui.autoanalysis.panels;

import java.awt.BorderLayout;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class AutoAnalysisPanel extends JPanel {
	private JSlider confidenceSlider;

	/**
	 * Create the panel.
	 */
	public AutoAnalysisPanel() {
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
		actionPanel.add(btnStartAnalysis, BorderLayout.SOUTH);
	}

	protected JSlider getConfidenceSlider() {
		return confidenceSlider;
	}
}
