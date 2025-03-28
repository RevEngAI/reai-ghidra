package ai.reveng.toolkit.ghidra.binarysimilarity.ui.settingsdialog;

import docking.DialogComponentProvider;

import javax.swing.*;
import java.awt.*;

/**
 * Dialog for setting the options for similarity searches:
 * - Number of Results
 * - Distance
 *
 */
public class ANNSettingsDialog extends DialogComponentProvider {
    private final JTextField numResultsBox;
    private final JTextField similarityBox;

    private double similarity;
    private int numResults;

    public ANNSettingsDialog() {
        super("ANN Settings", true, false, true, false);
        var settingsPanel = new JPanel();

        settingsPanel.setLayout(new GridLayout(0, 1));
        numResultsBox = new JTextField("10");
        settingsPanel.add(new JLabel("Number of Results"));
        settingsPanel.add(numResultsBox);

        settingsPanel.add(new JLabel("Similarity"));
        similarityBox = new JTextField("0.9");
        settingsPanel.add(similarityBox);

        addOKButton();
        addCancelButton();

        addWorkPanel(settingsPanel);
    }

    @Override
    protected void okCallback() {
        numResults = Integer.parseInt(numResultsBox.getText());
        similarity = Double.parseDouble(similarityBox.getText());
        close();
    }

    public int getNumResults(){
        return numResults;
    }

    public double getSimilarity(){
        return similarity;
    }


}
