package ai.reveng.toolkit.ghidra.binarysimilarity.ui.autounstrip;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.types.AutoUnstripResponse;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorComponent;

import javax.swing.*;
import java.awt.*;
import java.util.Objects;

import static ai.reveng.toolkit.ghidra.binarysimilarity.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;

public class AutoUnstripDialog extends DialogComponentProvider {
    private final AnalysisID analysisID;
    private final GhidraRevengService revengService;
    private final Program program;
    private AutoUnstripResponse autoUnstripResponse;

    // UI components
    private JLabel statusLabel;
    private JLabel matchesLabel;
    private JTextArea errorArea;
    private Timer pollTimer;
    private TaskMonitorComponent taskMonitorComponent;

    // Polling configuration
    private static final int POLL_INTERVAL_MS = 2000; // Poll every 2 seconds

    public AutoUnstripDialog(PluginTool tool, ProgramWithBinaryID analysisID) {
        super("Auto Unstrip", true);

        this.analysisID = analysisID.analysisID();
        this.program = analysisID.program();
        this.revengService = tool.getService(GhidraRevengService.class);
        this.taskMonitorComponent = new TaskMonitorComponent();
        // Initialize UI
        addDismissButton();

        addWorkPanel(buildMainPanel());

        // Start the auto unstrip process
        startAutoUnstrip();
    }

    private void startAutoUnstrip() {
        // Show initial status
        statusLabel.setText("Starting auto unstrip...");
        taskMonitorComponent.initialize(100);

        // Start polling timer
        pollTimer = new Timer(POLL_INTERVAL_MS, e -> pollAutoUnstripStatus());
        pollTimer.start();

        // Make initial call
        pollAutoUnstripStatus();
    }

    private void pollAutoUnstripStatus() {
        SwingUtilities.invokeLater(() -> {
            try {
                autoUnstripResponse = revengService.getApi().autoUnstrip(analysisID);
                updateUI();

                // Check if we're done
                if (autoUnstripResponse.progress() >= 100 || Objects.equals(autoUnstripResponse.status(), "COMPLETED")) {
                    stopPolling();
//                    taskMonitorComponent.setFinished();
                    taskMonitorComponent.setVisible(false);
                    importFunctionNames(autoUnstripResponse);
                }
            } catch (Exception e) {
                handleError("Failed to poll auto unstrip status: " + e.getMessage());
                stopPolling();
            }
        });
    }

    private void importFunctionNames(AutoUnstripResponse autoUnstripResponse) {


            var functionMgr = program.getFunctionManager();
            program.withTransaction("Apply Auto-Unstrip Function Names", () -> {
                        try {
                            var revengMatchNamespace = program.getSymbolTable().getOrCreateNameSpace(
                                    program.getGlobalNamespace(),
                                    REVENG_AI_NAMESPACE,
                                    SourceType.ANALYSIS);

                            autoUnstripResponse.matches().forEach(match -> {
                                Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(match.function_vaddr());
                                Function func = functionMgr.getFunctionAt(addr);
                                if (func == null) {
                                    return;
                                } else {
                                    try {
                                        func.setName(match.suggested_name(), SourceType.ANALYSIS);
                                        func.setParentNamespace(revengMatchNamespace);
                                    } catch (Exception e) {
                                        handleError("Failed to rename function at " + addr + ": " + e.getMessage());
                                    }
                                }
                            });
                        } catch (DuplicateNameException | InvalidInputException e) {
                            throw new RuntimeException(e);
                        }
                    }
                );
    }

    private void updateUI() {
        if (autoUnstripResponse == null) return;

        // Update progress bar
        taskMonitorComponent.setProgress(autoUnstripResponse.progress());
        taskMonitorComponent.setMessage(autoUnstripResponse.progress() + "%");

        // Update status
        statusLabel.setText("Status: " + autoUnstripResponse.status());

        // Update matches count
        int matchCount = autoUnstripResponse.matches() != null ? autoUnstripResponse.matches().size() : 0;
        matchesLabel.setText("Matches found: " + matchCount);

        // Handle error message
        if (autoUnstripResponse.error_message() != null && !autoUnstripResponse.error_message().isEmpty()) {
            errorArea.setText(autoUnstripResponse.error_message());
            errorArea.setVisible(true);
        } else {
            errorArea.setVisible(false);
        }

        // Show applied status if matches were applied
        if (autoUnstripResponse.applied() && matchCount > 0) {
            statusLabel.setText("Status: " + autoUnstripResponse.status() + " (Applied " + matchCount + " matches)");
        }
    }

    private void handleError(String message) {
        statusLabel.setText("Error occurred");
        errorArea.setText(message);
        errorArea.setVisible(true);
        taskMonitorComponent.setMessage("Error");
    }

    private void stopPolling() {
        if (pollTimer != null) {
            pollTimer.stop();
            pollTimer = null;
        }
    }

    private JComponent buildMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Description at the top
        JTextArea descriptionArea = new JTextArea(3, 60);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setEditable(false);
        descriptionArea.setBackground(panel.getBackground());
        descriptionArea.setText(
            """
            Automatically rename unknown functions in your analysis.
            The names are sourced by matching functions in your analysis to functions within the RevEng.AI dataset.
            """
        );
        panel.add(new JScrollPane(descriptionArea), BorderLayout.NORTH);

        // Progress panel in the center
        JPanel progressPanel = createProgressPanel();
        panel.add(progressPanel, BorderLayout.CENTER);

        // Error area at the bottom (initially hidden)
        errorArea = new JTextArea(5, 60);
        errorArea.setLineWrap(true);
        errorArea.setWrapStyleWord(true);
        errorArea.setEditable(false);
        errorArea.setBackground(Color.PINK);
        errorArea.setBorder(BorderFactory.createTitledBorder("Error Details"));
        errorArea.setVisible(false);
        panel.add(new JScrollPane(errorArea), BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createProgressPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.anchor = GridBagConstraints.WEST;

        // Progress bar
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(taskMonitorComponent, gbc);

        // Status label
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        statusLabel = new JLabel("Initializing...");
        panel.add(statusLabel, gbc);

        // Matches label
        gbc.gridx = 1;
        matchesLabel = new JLabel("Matches found: 0");
        panel.add(matchesLabel, gbc);

        return panel;
    }

    @Override
    protected void cancelCallback() {
        stopPolling();
        close();
    }
}
