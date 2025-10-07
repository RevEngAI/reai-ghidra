package ai.reveng.toolkit.ghidra.binarysimilarity.ui.autounstrip;

import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisID;
import ai.reveng.toolkit.ghidra.core.services.api.types.AutoUnstripResponse;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorComponent;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;

public class AutoUnstripDialog extends RevEngDialogComponentProvider {
    private final AnalysisID analysisID;
    private final GhidraRevengService revengService;
    private final Program program;
    private AutoUnstripResponse autoUnstripResponse;

    // UI components
    private JLabel statusLabel;
    private JLabel matchesLabel;
    private JTextArea errorArea;
    private JScrollPane errorScrollPane;
    private JPanel contentPanel;
    private Timer pollTimer;
    private TaskMonitorComponent taskMonitorComponent;
    private JTable resultsTable;
    private JScrollPane resultsScrollPane;
    private List<RenameResult> renameResults;

    // Polling configuration
    private static final int POLL_INTERVAL_MS = 2000; // Poll every 2 seconds

    // Inner class to hold rename results
    private static class RenameResult {
        final String originalName;
        final String newName;

        RenameResult(String originalName, String newName) {
            this.originalName = originalName;
            this.newName = newName;
        }
    }

    public AutoUnstripDialog(PluginTool tool, ProgramWithBinaryID analysisID) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Auto Unstrip", true);

        this.analysisID = analysisID.analysisID();
        this.program = analysisID.program();
        this.revengService = tool.getService(GhidraRevengService.class);
        this.taskMonitorComponent = new TaskMonitorComponent();
        this.renameResults = new ArrayList<>();
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
                                SourceType.ANALYSIS
                        );

                        autoUnstripResponse.matches().forEach(match -> {
                            Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(match.function_vaddr());
                            Function func = functionMgr.getFunctionAt(addr);

                            var revEngMangledName = match.suggested_name();
                            var revEngDemangledName = match.suggested_demangled_name();

                            if (
                                    func != null &&
                                    // Exclude thunks and external functions
                                    !func.isThunk() &&
                                    !func.isExternal() &&
                                    // Only accept valid names (no spaces)
                                    !revEngMangledName.contains(" ") &&
                                    !revEngDemangledName.contains(" ")
                            ) {
                                try {
                                    // Capture original name before renaming
                                    String originalName = func.getName();

                                    func.setName(revEngDemangledName, SourceType.ANALYSIS);
                                    func.setParentNamespace(revengMatchNamespace);

                                    // TODO: update the mangled name map

                                    // Add to rename results
                                    renameResults.add(new RenameResult(originalName, revEngDemangledName));

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

        // Show results table after import is complete
        SwingUtilities.invokeLater(() -> updateResultsTable());
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

        // Handle error message - dynamically add/remove error panel
        if (autoUnstripResponse.error_message() != null && !autoUnstripResponse.error_message().isEmpty()) {
            showError(autoUnstripResponse.error_message());
        } else {
            hideError();
        }

        // Show applied status if matches were applied
        if (autoUnstripResponse.applied() && matchCount > 0) {
            statusLabel.setText("Status: " + autoUnstripResponse.status() + " (Applied " + matchCount + " matches)");
        }

        // Update results table
        updateResultsTable();
    }

    private void updateResultsTable() {
        DefaultTableModel model = new DefaultTableModel(new Object[]{"Original Name", "New Name"}, 0);
        for (RenameResult result : renameResults) {
            model.addRow(new Object[]{result.originalName, result.newName});
        }
        resultsTable.setModel(model);

        // Update the dynamic title
        int renameCount = renameResults.size();
        String title = "Renamed " + renameCount + " functions identified by the RevEng.AI dataset";
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder(title));

        // Fix table header appearance
        resultsTable.getTableHeader().setOpaque(false);
        resultsTable.getTableHeader().setBackground(UIManager.getColor("TableHeader.background"));
        resultsTable.getTableHeader().setForeground(UIManager.getColor("TableHeader.foreground"));
    }

    private void handleError(String message) {
        statusLabel.setText("Error occurred");
        showError(message);
        taskMonitorComponent.setMessage("Error");
    }

    private void showError(String message) {
        errorArea.setText(message);
        // Only add the error panel if it's not already added
        if (errorScrollPane.getParent() == null) {
            contentPanel.add(errorScrollPane, BorderLayout.SOUTH);
            contentPanel.revalidate();
            contentPanel.repaint();
        }
    }

    private void hideError() {
        // Only remove the error panel if it's currently added
        if (errorScrollPane.getParent() != null) {
            contentPanel.remove(errorScrollPane);
            contentPanel.revalidate();
            contentPanel.repaint();
        }
    }

    private void stopPolling() {
        if (pollTimer != null) {
            pollTimer.stop();
            pollTimer = null;
        }
    }

    private JComponent buildMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());

        // Create title panel
        JPanel titlePanel = createTitlePanel("Automatically rename unknown functions");
        panel.add(titlePanel, BorderLayout.NORTH);

        // Create content panel for description and progress
        contentPanel = new JPanel(new BorderLayout());

        // Progress panel in the center
        JPanel progressPanel = createProgressPanel();
        contentPanel.add(progressPanel, BorderLayout.CENTER);

        // Initialize error area but don't add it to the panel yet
        errorArea = new JTextArea(5, 60);
        errorArea.setLineWrap(true);
        errorArea.setWrapStyleWord(true);
        errorArea.setEditable(false);
        errorArea.setBackground(Color.PINK);
        errorArea.setBorder(BorderFactory.createTitledBorder("Error Details"));
        errorScrollPane = new JScrollPane(errorArea);
        // Note: Error panel is not added here - it will be added dynamically when needed

        // Results table
        resultsTable = new JTable();
        resultsScrollPane = new JScrollPane(resultsTable);
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder("Rename Results"));
        contentPanel.add(resultsScrollPane, BorderLayout.SOUTH);

        panel.add(contentPanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createProgressPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.anchor = GridBagConstraints.WEST;

        // Progress bar
        gbc.gridx = 0;
        gbc.gridy = 0;
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
