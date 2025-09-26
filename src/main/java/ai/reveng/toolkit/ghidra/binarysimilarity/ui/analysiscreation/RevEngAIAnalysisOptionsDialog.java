package ai.reveng.toolkit.ghidra.binarysimilarity.ui.analysiscreation;

import ai.reveng.toolkit.ghidra.plugins.AnalysisManagementPlugin;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisScope;
import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class RevEngAIAnalysisOptionsDialog extends DialogComponentProvider {
    private final JComboBox<ModelName> modelComboBox;
    private final JCheckBox advancedAnalysisCheckBox;
    private final JCheckBox dynamicExecutionCheckBox;
    private final Program program;
    private final PluginTool tool;
    private final AnalysisManagementPlugin plugin;
    private final JRadioButton privateScope;
    private final JRadioButton publicScope;
    private final JTextField tagsTextBox;
    private final JCheckBox scrapeExternalTagsBox;
    private final JCheckBox identifyCapabilitiesCheckBox;
    private final JCheckBox identifyCVECheckBox;
    private final JCheckBox generateSBOMCheckBox;
    private final JComboBox<String> architectureComboBox;

    public RevEngAIAnalysisOptionsDialog(AnalysisManagementPlugin plugin, Program program) {
        super("Configure Analysis for %s".formatted(program.getName()), true, false, true, true);
        this.program = program;
        this.tool = plugin.getTool();
        this.plugin = plugin;

        var reService = tool.getService(GhidraRevengService.class);

        var workPanel = new JPanel();
        workPanel.setLayout(new BoxLayout(workPanel, BoxLayout.Y_AXIS));
        addWorkPanel(workPanel);


        // Add Platform Drop Down
        var platformComboBox = new JComboBox<>(new String[]{
                "Auto", "windows", "linux",
//                "macos", "android"
        });
        platformComboBox.setEditable(false);
        // Center the text
        platformComboBox.setAlignmentX(Component.CENTER_ALIGNMENT);
        platformComboBox.setMaximumSize(platformComboBox.getPreferredSize());
        var platformLabel = new JLabel("Select Platform");
        platformLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(platformLabel);
        workPanel.add(platformComboBox);



        // Add Drop down for AnalysisScope
        // Currently just public and private, but in the future this will include teams
        var scopePanel = new JPanel();
        scopePanel.setLayout(new BoxLayout(scopePanel, BoxLayout.X_AXIS));
        privateScope = new JRadioButton("Private to you");
        publicScope = new JRadioButton("Public access");
        privateScope.setSelected(true);

        var group = new ButtonGroup();
        group.add(privateScope);
        group.add(publicScope);
        scopePanel.add(privateScope);
        scopePanel.add(publicScope);

        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        var scopeLabel = new JLabel("Select Analysis Scope");
        scopeLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(scopeLabel);
        workPanel.add(scopePanel);

        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        // Add ISA Drop Down
        // Add drop Down menu for the architecture
        architectureComboBox = new JComboBox<>(new String[]{
                "Auto", "x86", "x86_64"
        });
        architectureComboBox.setEditable(false);
        architectureComboBox.setMaximumSize(architectureComboBox.getPreferredSize());
        var architectureLabel = new JLabel("Select Architecture");
        architectureLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(architectureLabel);
        workPanel.add(architectureComboBox);

        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        // Add drop Down menu for the model name
        modelComboBox = new JComboBox<ModelName>();
        modelComboBox.setEditable(false);
        modelComboBox.setMaximumSize(new Dimension(200, 20));
        var modelLabel = new JLabel("Select Model");
        modelLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(modelLabel);
        workPanel.add(modelComboBox);

        this.executeProgressTask(
                new Task("Get Available Models", false, false, false) {
                    @Override
                    public void run(TaskMonitor monitor) throws CancelledException {
                        var models = reService.getAvailableModels();
                        // Populate the modelComboBox with the available models
                        modelComboBox.removeAllItems();
                        for (var model : models) {
                            modelComboBox.addItem(model);
                        }
                        var bestModel = reService.getModelNameForProgram(program, models);
                        // Select that entry
                        if (bestModel != null) {
                            modelComboBox.setSelectedItem(bestModel);
                        }
                    }
                }, 0
        );

        workPanel.add(Box.createVerticalGlue());

        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));

        // Add Two Check boxes for Dynamic Execution and Advanced Analysis next to each other (horizantally)
        var checkBoxPanel = new JPanel();
//        checkBoxPanel.setLayout(new BoxLayout(checkBoxPanel, BoxLayout.X_AXIS));
        checkBoxPanel.setLayout(new GridLayout(0, 2));
        dynamicExecutionCheckBox = new JCheckBox("Dynamic Execution");
        dynamicExecutionCheckBox.setToolTipText("Include Dynamic Execution inside a Sandbox Environment with the Analysis");

        advancedAnalysisCheckBox = new JCheckBox("Advanced Analysis");
        advancedAnalysisCheckBox.setToolTipText("Run dataflow analysis for advanced analysis. Can increase analysis cost by 500%");


        // Add a check box for quick mode
        scrapeExternalTagsBox = new JCheckBox("Get External Tags");
        scrapeExternalTagsBox.setToolTipText("Scrape external tags from VirusTotal (requires configured API key)");

        // Add check box for identifiying capabilities
        identifyCapabilitiesCheckBox = new JCheckBox("Identify Capabilities");
        identifyCapabilitiesCheckBox.setToolTipText("Identify capabilities of the binary");

        // Add Check box for identifying CVEs
        identifyCVECheckBox = new JCheckBox("Identify CVEs");
        identifyCVECheckBox.setToolTipText("Identify CVEs in the binary");

        // Add Check box for generating the SBOM
        generateSBOMCheckBox = new JCheckBox("Generate SBOM");
        generateSBOMCheckBox.setToolTipText("Generate a Software Bill of Materials (SBOM) for the binary");

//        checkBoxPanel.add(dynamicExecutionCheckBox);
//        checkBoxPanel.add(advancedAnalysisCheckBox);
//        checkBoxPanel.add(scrapeExternalTagsBox);
//        checkBoxPanel.add(identifyCapabilitiesCheckBox);
//        checkBoxPanel.add(identifyCVECheckBox);
//        checkBoxPanel.add(generateSBOMCheckBox);
//        workPanel.add(checkBoxPanel);

        // Add custom tags field
        workPanel.add(new JSeparator(SwingConstants.HORIZONTAL));
        tagsTextBox = new JTextField();
        tagsTextBox.setToolTipText("Custom tags for the analysis, as comma separated list");
        tagsTextBox.setColumns(20);
        tagsTextBox.setMaximumSize(new Dimension(200, 20));
        var tagsLabel = new JLabel("Custom Tags");
        tagsLabel.setToolTipText("Custom tags for the analysis, as comma separated list");
        tagsLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        tagsTextBox.setAlignmentX(Component.CENTER_ALIGNMENT);
        workPanel.add(tagsLabel);
        workPanel.add(tagsTextBox);

        addCancelButton();
        addOKButton();

        okButton.setText("Start Analysis");
    }

    @Override
    protected void okCallback() {
        var reService = tool.getService(GhidraRevengService.class);
        // The analysis task is executed in the tool, and not the dialog
        tool.execute(
                new Task("Running RevEng.AI Analysis", true, false, false) {
                    @Override
                    public void run(TaskMonitor monitor) throws CancelledException {
                        monitor.setMessage("Uploading Binary");
                        reService.upload(program);
                        monitor.setMessage("Exporting Function Boundaries");
                        var options = AnalysisOptionsBuilder.forProgram(program);
                        options.modelName((ModelName) modelComboBox.getSelectedItem());

                        options.skipScraping(!scrapeExternalTagsBox.isSelected());
                        options.skipCapabilities(!identifyCapabilitiesCheckBox.isSelected());

                        options.skipSBOM(!generateSBOMCheckBox.isSelected());
                        options.skipCVE(!identifyCVECheckBox.isSelected());

                        options.advancedAnalysis(advancedAnalysisCheckBox.isSelected());
                        options.dynamicExecution(dynamicExecutionCheckBox.isSelected());

                        if (publicScope.isEnabled()) {
                            options.scope(AnalysisScope.PUBLIC);
                        } else {
                            options.scope(AnalysisScope.PRIVATE);
                        }

                        options.addTags(List.of(tagsTextBox.getText().split(",")));
                        options.architecture((String) architectureComboBox.getSelectedItem());

                        monitor.setMessage("Sending Analysis Request");

                        var programWithBinaryID = reService.startAnalysis(program, options);
                        monitor.setMessage("Waiting for Analysis to finish");
                        // Create a new ProgramWithBinaryID
                        var finalAnalysisStatus = reService.waitForFinishedAnalysis(monitor, programWithBinaryID, plugin);
                        tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent("RevEng.AI Analysis", programWithBinaryID, finalAnalysisStatus));
                    }
                }, 0
        );

        // Close dialog
        close();
    }

    @Override
    public JComponent getComponent() {
        return super.getComponent();
    }
}
