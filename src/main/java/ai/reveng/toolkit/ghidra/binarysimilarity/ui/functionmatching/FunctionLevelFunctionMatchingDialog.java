package ai.reveng.toolkit.ghidra.binarysimilarity.ui.functionmatching;

import ai.reveng.model.*;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.BinarySelectionPanel;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.CollectionSelectionPanel;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.components.SelectableItem;
import ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog.RevEngDialogComponentProvider;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionID;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorComponent;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;

public class FunctionLevelFunctionMatchingDialog extends RevEngDialogComponentProvider {
    private final GhidraRevengService revengService;
    private final ProgramWithBinaryID programWithBinaryID;
    private final Function function;

    // UI Components
    private JPanel contentPanel;
    private JTable resultsTable;
    private JScrollPane resultsScrollPane;
    private CollectionSelectionPanel collectionSelector;
    private BinarySelectionPanel binarySelector;
    private JTextField functionFilterField;
    private JSlider thresholdSlider;
    private JLabel thresholdValueLabel;
    private JCheckBox debugSymbolsCheckBox;
    private JCheckBox userSubmittedDebugSymbolsCheckBox;
    private JLabel statusLabel;
    private JTextArea errorArea;
    private JScrollPane errorScrollPane;
    private final TaskMonitorComponent taskMonitorComponent;
    private Timer pollTimer;
    private JPanel renameButtonsPanel;

    // Data
    private Basic analysisBasicInfo;
    private FunctionMatchingBatchResponse functionMatchingResponse;
    private final List<FunctionMatchResult> functionMatchResults;
    private final List<FunctionMatchResult> filteredFunctionMatchResults;

    // Polling configuration
    private static final int POLL_INTERVAL_MS = 2000; // Poll every 2 seconds

    // Inner class to hold function match results
    private record FunctionMatchResult(
            String virtualAddress,
            String functionName,
            String bestMatchName,
            String bestMatchMangledName,
            String similarity,
            String confidence,
            String matchedHash,
            String binary,
            Long matcherFunctionId  // This is the function that we match from no the matched function's ID!
    ) {
    }

    public FunctionLevelFunctionMatchingDialog(PluginTool tool, ProgramWithBinaryID programWithBinaryID, Function function) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "Function Matching", true);

        this.revengService = tool.getService(GhidraRevengService.class);
        this.taskMonitorComponent = new TaskMonitorComponent(false, true);
        this.functionMatchResults = new ArrayList<>();
        this.filteredFunctionMatchResults = new ArrayList<>();
        this.programWithBinaryID = programWithBinaryID;
        this.function = function;

        try {
            this.analysisBasicInfo = revengService.getBasicDetailsForAnalysis(programWithBinaryID.analysisID());
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null,
                    "Failed to fetch analysis details: " + e.getMessage(),
                    "Error",
                    JOptionPane.ERROR_MESSAGE);
            close();
            return;
        }

        // Initialize UI
        addDismissButton();
        addWorkPanel(buildMainPanel());

        // Set dialog size to be wider
        setPreferredSize(1000, 800);

        // Don't start function matching automatically - wait for user to click Match button
        statusLabel.setText("Ready - adjust filters and click 'Match Functions' to begin search");
        taskMonitorComponent.setVisible(false);
    }

    private void startFunctionMatching() {
        // Show initial status
        statusLabel.setText("Starting function matching...");
        taskMonitorComponent.initialize(100);

        // Start polling timer
        pollTimer = new Timer(POLL_INTERVAL_MS, e -> pollFunctionMatchingStatus());
        pollTimer.start();

        // Make initial call
        pollFunctionMatchingStatus();
    }

    private void pollFunctionMatchingStatus() {
        SwingUtilities.invokeLater(() -> {
            try {
                var request = new AnalysisFunctionMatchingRequest();
                request.setMinSimilarity(BigDecimal.valueOf(getThreshold()));

                var functionID = revengService.getFunctionIDFor(function);

                var functionIds = new ArrayList<Long>();
                functionIds.add(functionID.get().value())

                var filters = new FunctionMatchingFilters();
                filters.setCollectionIds(collectionSelector.getSelectedCollectionIds().stream().toList());
                filters.setBinaryIds(binarySelector.getSelectedBinaryIds().stream().toList());
                filters.setFunctionIds(functionIds);

                if (isDebugSymbolsEnabled()) {
                    var debugTypes = new ArrayList<FunctionMatchingFilters.DebugTypesEnum>();
                    debugTypes.add(FunctionMatchingFilters.DebugTypesEnum.SYSTEM);

                    if (isUserSubmittedDebugSymbolsEnabled()) {
                        debugTypes.add(FunctionMatchingFilters.DebugTypesEnum.USER);
                    }

                    filters.setDebugTypes(debugTypes);
                }

                request.setFilters(filters);

                functionMatchingResponse = revengService.getFunctionMatchingForAnalysis(programWithBinaryID.analysisID(), request);
                updateUI();

                // Check if we're done
                if (functionMatchingResponse.getProgress() != null &&
                    (functionMatchingResponse.getProgress() >= 100 || Objects.equals(functionMatchingResponse.getStatus(), "COMPLETED"))) {
                    stopPolling();
                    taskMonitorComponent.setVisible(false);
                    processFunctionMatchingResults(functionMatchingResponse);
                }
            } catch (Exception e) {
                handleError("Failed to poll function matching status: " + e.getMessage());
                stopPolling();
            }
        });
    }

    private void processFunctionMatchingResults(FunctionMatchingBatchResponse response) {
        functionMatchResults.clear();

        var functionMap = revengService.getFunctionMap(programWithBinaryID.program());

        response.getMatches().forEach(matchResult -> {

            // Process each matched function in this result
            matchResult.getMatchedFunctions().forEach(match -> {

                // Retrieve the local function name
                Function localFunction = functionMap.get(new FunctionID(matchResult.getFunctionId()));

                if (localFunction == null) {
                    // If we can't find the local function, skip this match
                    return;
                }

                // Extract data from the MatchedFunction
                String virtualAddress = String.format("%08x", match.getFunctionVaddr());
                String functionName = localFunction.getName();
                String bestMatchName = match.getFunctionName();
                String bestMatchMangledName = match.getMangledName();
                String similarity = match.getSimilarity() != null ?
                    String.format("%.2f%%", match.getSimilarity().doubleValue()) : "N/A";
                String confidence = match.getConfidence() != null ?
                    String.format("%.2f%%", match.getConfidence().doubleValue()) : "N/A";
                String matchedHash = match.getSha256Hash();
                String binary = match.getBinaryName();
                Long matcherFunctionId = matchResult.getFunctionId();

                functionMatchResults.add(new FunctionMatchResult(
                    virtualAddress,
                    functionName,
                    bestMatchName,
                    bestMatchMangledName,
                    similarity,
                    confidence,
                    matchedHash,
                    binary,
                    matcherFunctionId
                ));
            });
        });

        // Apply any existing function filter after getting results
        onFunctionFilterChanged();

        // Update results table after processing is complete
        SwingUtilities.invokeLater(this::updateResultsTable);
    }

    private void updateUI() {
        if (functionMatchingResponse == null) return;

        // Update progress bar
        if (functionMatchingResponse.getProgress() != null) {
            taskMonitorComponent.setProgress(functionMatchingResponse.getProgress());
            taskMonitorComponent.setMessage(functionMatchingResponse.getProgress() + "%");
        }

        // Update status
        if (functionMatchingResponse.getStatus() != null) {
            statusLabel.setText("Status: " + functionMatchingResponse.getStatus());
        }

        // Handle error message - dynamically add/remove error panel
        if (functionMatchingResponse.getErrorMessage() != null && !functionMatchingResponse.getErrorMessage().isEmpty()) {
            showError(functionMatchingResponse.getErrorMessage());
        } else {
            hideError();
        }

        // Update results table
        updateResultsTable();
    }

    private void updateResultsTable() {
        // Determine which results to show based on whether we have an active filter
        String filterText = functionFilterField != null ? functionFilterField.getText().trim() : "";
        List<FunctionMatchResult> resultsToShow;

        if (filterText.isEmpty()) {
            // No filter text, show all results
            resultsToShow = functionMatchResults;
        } else {
            // Filter text exists, show filtered results (even if empty)
            resultsToShow = filteredFunctionMatchResults;
        }

        DefaultTableModel model = new DefaultTableModel(
            new Object[]{"Virtual Address", "Function Name", "Matched Function", "Similarity", "Confidence", "Matched Hash", "Matched Binary"},
            0
        );
        for (FunctionMatchResult result : resultsToShow) {
            model.addRow(new Object[]{
                result.virtualAddress, result.functionName, result.bestMatchName,
                result.similarity, result.confidence, result.matchedHash, result.binary
            });
        }
        resultsTable.setModel(model);

        // Update the dynamic title with filtered count
        int totalMatchCount = functionMatchResults.size();
        int displayedMatchCount = resultsToShow.size();
        String title;
        if (filterText.isEmpty()) {
            title = "Function Matching Results (" + totalMatchCount + " matches found)";
        } else {
            title = "Function Matching Results (" + displayedMatchCount + " of " + totalMatchCount + " matches shown)";
        }
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder(title));

        // Show/hide rename buttons based on whether we have results
        boolean hasResults = displayedMatchCount > 0;
        renameButtonsPanel.setVisible(hasResults);

        // Enable table selection model for rename operations
        if (hasResults) {
            resultsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            resultsTable.setRowSelectionAllowed(true);
        }

        // Fix table header appearance
        resultsTable.getTableHeader().setOpaque(false);
        resultsTable.getTableHeader().setBackground(UIManager.getColor("TableHeader.background"));
        resultsTable.getTableHeader().setForeground(UIManager.getColor("TableHeader.foreground"));

        // Set column widths and fonts
        if (resultsTable.getColumnCount() > 0) {
            // Set monospace font for Virtual Address column
            resultsTable.getColumnModel().getColumn(0).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
                @Override
                public Component getTableCellRendererComponent(JTable table, Object value,
                                                               boolean isSelected, boolean hasFocus, int row, int column) {
                    Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                    c.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
                    return c;
                }
            });

            // Set color-coded renderer for Similarity column (index 3)
            resultsTable.getColumnModel().getColumn(3).setCellRenderer(new PercentageColorCellRenderer());

            // Set color-coded renderer for Confidence column (index 4)
            resultsTable.getColumnModel().getColumn(4).setCellRenderer(new PercentageColorCellRenderer());

            // Set column widths
            resultsTable.getColumnModel().getColumn(0).setPreferredWidth(100);  // Virtual Address
            resultsTable.getColumnModel().getColumn(1).setPreferredWidth(150);  // Function Name
            resultsTable.getColumnModel().getColumn(2).setPreferredWidth(150);  // Best Match
            resultsTable.getColumnModel().getColumn(3).setPreferredWidth(80);   // Similarity
            resultsTable.getColumnModel().getColumn(4).setPreferredWidth(80);   // Confidence
            resultsTable.getColumnModel().getColumn(5).setPreferredWidth(100);  // Matched Hash
            resultsTable.getColumnModel().getColumn(6).setPreferredWidth(120);  // Binary

            // Set minimum widths
            resultsTable.getColumnModel().getColumn(0).setMinWidth(80);
            resultsTable.getColumnModel().getColumn(1).setMinWidth(100);
            resultsTable.getColumnModel().getColumn(2).setMinWidth(100);
            resultsTable.getColumnModel().getColumn(3).setMinWidth(60);
            resultsTable.getColumnModel().getColumn(4).setMinWidth(60);
            resultsTable.getColumnModel().getColumn(5).setMinWidth(80);
            resultsTable.getColumnModel().getColumn(6).setMinWidth(80);
        }
    }

    /**
     * Custom cell renderer that colors percentage values based on their range
     */
    private static class PercentageColorCellRenderer extends javax.swing.table.DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (value instanceof String percentageStr) {
                Color textColor = getColorForPercentage(percentageStr);

                if (!isSelected) {
                    // Set text color based on percentage value
                    c.setForeground(textColor);
                    // Keep default background color
                    c.setBackground(table.getBackground());
                } else {
                    // Keep default selection colors when selected
                    c.setBackground(table.getSelectionBackground());
                    c.setForeground(table.getSelectionForeground());
                }
            }

            return c;
        }

        /**
         * Get the text color based on percentage value
         */
        private Color getColorForPercentage(String percentageStr) {
            try {
                // Remove the % symbol and parse as double
                String numStr = percentageStr.replace("%", "").trim();
                if (numStr.equals("N/A")) {
                    return Color.BLACK; // Default color for N/A values
                }

                double percentage = Double.parseDouble(numStr);

                if (percentage >= 0 && percentage <= 1) {
                    return new Color(255, 0, 0); // Red
                } else if (percentage > 1 && percentage <= 50) {
                    return new Color(128, 0, 128); // Purple
                } else if (percentage > 50 && percentage <= 70) {
                    return new Color(255, 165, 0); // Orange
                } else if (percentage > 70 && percentage <= 90) {
                    return new Color(200, 140, 0); // Darker yellow for better visibility
                } else if (percentage > 90 && percentage <= 95) {
                    return new Color(34, 139, 34); // Forest Green
                } else if (percentage > 95 && percentage <= 100) {
                    return new Color(0, 100, 0); // Dark Green
                } else {
                    return Color.BLACK; // Default for out-of-range values
                }
            } catch (NumberFormatException e) {
                return Color.BLACK; // Default color for unparseable values
            }
        }
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
        JPanel titlePanel = createTitlePanel("Find matching functions for this function");
        panel.add(titlePanel, BorderLayout.NORTH);

        // Create content panel
        contentPanel = new JPanel(new BorderLayout());

        // Create top panel with progress and filters
        JPanel topPanel = new JPanel(new BorderLayout());

        // Progress panel at the top
        JPanel progressPanel = createProgressPanel();
        topPanel.add(progressPanel, BorderLayout.NORTH);

        // Create filter panel with 3-row, 2-column layout
        JPanel filterPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weighty = 0;

        // Row 0: Function filter text field (100% width, spans both columns)
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(10, 0, 10, 0);
        filterPanel.add(createFunctionFilterPanel(), gbc);

        // Row 1, Col 0: Collection selector (50% width)
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(0, 0, 10, 10); // padding between components
        filterPanel.add(createCollectionSelectorPanel(), gbc);

        // Row 1, Col 1: Binary selector (50% width) - no right padding
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(0, 0, 10, 0); // no right padding for last column
        filterPanel.add(createBinarySelectorPanel(), gbc);

        // Row 2, Col 0: Threshold panel (50% width)
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(0, 0, 0, 10); // padding between components
        filterPanel.add(createThresholdPanel(), gbc);

        // Row 2, Col 1: Debug symbols toggle (50% width) - no right padding
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.weightx = 0.5;
        gbc.insets = new Insets(0, 0, 0, 0); // no right padding for last column
        filterPanel.add(createDebugSymbolsPanel(), gbc);

        topPanel.add(filterPanel, BorderLayout.CENTER);
        contentPanel.add(topPanel, BorderLayout.NORTH);

        // Match button panel - positioned between filters and results
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton matchButton = new JButton("Match Functions");
        matchButton.addActionListener(e -> onMatchButtonClicked());
        buttonPanel.add(matchButton);

        // Rename buttons panel - positioned between filters and results
        renameButtonsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        JButton renameSelectedButton = new JButton("Rename Selected");
        renameSelectedButton.addActionListener(e -> onRenameSelectedButtonClicked());
        renameButtonsPanel.add(renameSelectedButton);

        // Create a center panel to hold the button and results
        JPanel centerPanel = new JPanel(new BorderLayout());
        centerPanel.add(buttonPanel, BorderLayout.NORTH);

        // Initialize error area but don't add it to the panel yet
        errorArea = new JTextArea(5, 60);
        errorArea.setLineWrap(true);
        errorArea.setWrapStyleWord(true);
        errorArea.setEditable(false);
        errorArea.setBackground(Color.PINK);
        errorArea.setBorder(BorderFactory.createTitledBorder("Error Details"));
        errorScrollPane = new JScrollPane(errorArea);
        // Note: Error panel is not added here - it will be added dynamically when needed

        // Results table with rename buttons container
        JPanel resultsContainer = new JPanel(new BorderLayout());

        // Results table
        resultsTable = new JTable();
        resultsScrollPane = new JScrollPane(resultsTable);
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder("Function Matching Results"));
        resultsContainer.add(resultsScrollPane, BorderLayout.CENTER);

        // Rename buttons panel - initially hidden, will be shown when results are available
        renameButtonsPanel.setVisible(false);
        resultsContainer.add(renameButtonsPanel, BorderLayout.SOUTH);

        centerPanel.add(resultsContainer, BorderLayout.CENTER);

        contentPanel.add(centerPanel, BorderLayout.CENTER);

        panel.add(contentPanel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createProgressPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 10, 0, 10);
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

        return panel;
    }

    private JPanel createCollectionSelectorPanel() {
        // Create collection selection panel
        collectionSelector = new CollectionSelectionPanel(
                query -> revengService.searchCollectionsWithIds(query, analysisBasicInfo.getModelName()),
                3 // Minimum 3 characters before API calls
        );
        collectionSelector.addCollectionSelectionListener(this::onCollectionSelectionChanged);

        return collectionSelector;
    }

    private JPanel createBinarySelectorPanel() {
        // Create binary selection panel
        binarySelector = new BinarySelectionPanel(
                query -> revengService.searchBinariesWithIds(query, analysisBasicInfo.getModelName()),
                3 // Minimum 3 characters before API calls
        );
        binarySelector.addBinarySelectionListener(this::onBinarySelectionChanged);

        return binarySelector;
    }

    /**
     * Creates the threshold slider panel
     */
    private JPanel createThresholdPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Minimum similarity"));

        // Create slider (0-100)
        thresholdSlider = new JSlider(0, 100, 70); // min=0, max=100, initial=70
        thresholdSlider.setMajorTickSpacing(25);
        thresholdSlider.setMinorTickSpacing(5);
        thresholdSlider.setPaintTicks(true);
        thresholdSlider.setPaintLabels(true);

        // Create value label
        thresholdValueLabel = new JLabel("70%", SwingConstants.CENTER);
        thresholdValueLabel.setFont(thresholdValueLabel.getFont().deriveFont(Font.BOLD, 14f));

        // Add change listener to update label and trigger filtering
        thresholdSlider.addChangeListener(e -> {
            int value = thresholdSlider.getValue();
            thresholdValueLabel.setText(value + "%");
            if (!thresholdSlider.getValueIsAdjusting()) {
                onThresholdChanged(value);
            }
        });

        // Layout components
        JPanel sliderPanel = new JPanel(new BorderLayout());
        sliderPanel.add(thresholdSlider, BorderLayout.CENTER);
        sliderPanel.add(thresholdValueLabel, BorderLayout.EAST);

        panel.add(sliderPanel, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Creates the debug symbols toggle panel
     */
    private JPanel createDebugSymbolsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Debug symbols"));

        // Create main panel to hold both checkboxes vertically with fixed height
        JPanel checkboxPanel = new JPanel();
        checkboxPanel.setLayout(new BoxLayout(checkboxPanel, BoxLayout.Y_AXIS));

        // Set a preferred size to match the similarity panel height
        // The similarity panel has a slider + label, so we match that height
        checkboxPanel.setPreferredSize(new Dimension(0, 52));
        checkboxPanel.setMinimumSize(new Dimension(0, 52));

        // Create main debug symbols checkbox
        debugSymbolsCheckBox = new JCheckBox("Only include functions with debug symbols", false);
        debugSymbolsCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        debugSymbolsCheckBox.addActionListener(e -> {
            boolean selected = debugSymbolsCheckBox.isSelected();
            userSubmittedDebugSymbolsCheckBox.setVisible(selected);
            onDebugSymbolsChanged(selected);
        });

        // Create user submitted debug symbols checkbox (initially hidden)
        userSubmittedDebugSymbolsCheckBox = new JCheckBox("Include user submitted debug symbols", false);
        userSubmittedDebugSymbolsCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        userSubmittedDebugSymbolsCheckBox.setVisible(false);
        userSubmittedDebugSymbolsCheckBox.addActionListener(e -> onUserSubmittedDebugSymbolsChanged(userSubmittedDebugSymbolsCheckBox.isSelected()));

        // Create a wrapper panel for the second checkbox to add indentation while maintaining left alignment
        JPanel indentedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        indentedPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        indentedPanel.add(userSubmittedDebugSymbolsCheckBox);

        // Add vertical glue to push checkboxes to the top and maintain consistent spacing
        checkboxPanel.add(debugSymbolsCheckBox);
        checkboxPanel.add(indentedPanel);
        checkboxPanel.add(Box.createVerticalGlue()); // This fills remaining space

        panel.add(checkboxPanel, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Creates the function filter text field panel
     */
    private JPanel createFunctionFilterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Function filter"));

        // Create text field for function name filtering
        functionFilterField = new JTextField();
        functionFilterField.setPreferredSize(new Dimension(0, 30));
        functionFilterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                onFunctionFilterChanged();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                onFunctionFilterChanged();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                onFunctionFilterChanged();
            }
        });

        panel.add(functionFilterField, BorderLayout.CENTER);

        return panel;
    }

    /**
     * Called when collection selection changes
     */
    private void onCollectionSelectionChanged(Set<SelectableItem> selectedCollections) {
        Set<Integer> collectionIds = selectedCollections.stream()
                .map(SelectableItem::getId)
                .collect(Collectors.toSet());
        Set<String> collectionNames = selectedCollections.stream()
                .map(SelectableItem::getName)
                .collect(Collectors.toSet());

        Msg.info(this, "Selected collections: " + collectionNames + " (IDs: " + collectionIds + ")");
        // No longer automatically trigger filtering - user must click Match button
    }

    /**
     * Called when binary selection changes
     */
    private void onBinarySelectionChanged(Set<SelectableItem> selectedBinaries) {
        Set<Integer> binaryIds = selectedBinaries.stream()
                .map(SelectableItem::getId)
                .collect(Collectors.toSet());
        Set<String> binaryNames = selectedBinaries.stream()
                .map(SelectableItem::getName)
                .collect(Collectors.toSet());

        Msg.info(this, "Selected binaries: " + binaryNames + " (IDs: " + binaryIds + ")");
    }

    /**
     * Called when threshold slider value changes
     */
    private void onThresholdChanged(int threshold) {
        Msg.info(this, "Threshold changed to: " + threshold);
    }

    /**
     * Called when debug symbols checkbox state changes
     */
    private void onDebugSymbolsChanged(boolean includeDebugSymbols) {
        Msg.info(this, "Debug symbols filter changed to: " + includeDebugSymbols);
    }

    /**
     * Called when user submitted debug symbols checkbox state changes
     */
    private void onUserSubmittedDebugSymbolsChanged(boolean includeUserSubmittedDebugSymbols) {
        Msg.info(this, "User submitted debug symbols filter changed to: " + includeUserSubmittedDebugSymbols);
    }

    /**
     * Called when function filter text field value changes
     */
    private void onFunctionFilterChanged() {
        String filterText = functionFilterField.getText().trim().toLowerCase();

        // Apply local filtering to the function match results
        filteredFunctionMatchResults.clear();
        if (!filterText.isEmpty()) {
            // Filter results based on function name containing the filter text
            filteredFunctionMatchResults.addAll(
                functionMatchResults.stream()
                    .filter(result -> result.functionName.toLowerCase().contains(filterText))
                    .toList()
            );
        }

        // Update results table with filtered results
        updateResultsTable();
    }

    /**
     * Gets the current threshold value
     */
    public int getThreshold() {
        return thresholdSlider != null ? thresholdSlider.getValue() : 50;
    }

    /**
     * Gets the current debug symbols setting
     */
    public boolean isDebugSymbolsEnabled() {
        return debugSymbolsCheckBox != null && debugSymbolsCheckBox.isSelected();
    }

    /**
     * Gets the current user submitted debug symbols setting
     */
    public boolean isUserSubmittedDebugSymbolsEnabled() {
        return userSubmittedDebugSymbolsCheckBox != null && userSubmittedDebugSymbolsCheckBox.isSelected();
    }

    /**
     * Triggers function matching based on current filter settings
     */
    private void filterResults() {
        Set<Integer> selectedCollectionIds = collectionSelector.getSelectedCollectionIds();
        Set<Integer> selectedBinaryIds = binarySelector.getSelectedBinaryIds();
        Set<String> selectedCollectionNames = collectionSelector.getSelectedCollectionNames();
        Set<String> selectedBinaryNames = binarySelector.getSelectedBinaryNames();
        int threshold = getThreshold();
        boolean includeDebugSymbols = isDebugSymbolsEnabled();
        boolean includeUserSubmittedDebugSymbols = isUserSubmittedDebugSymbolsEnabled();

        // Stop any existing polling
        stopPolling();

        // Clear previous results
        functionMatchResults.clear();
        updateResultsTable();
        hideError();

        // Only start function matching if we have meaningful filter criteria
        // For now, we'll start matching when user adjusts any filter
        Msg.info(this, "Starting function matching with filters - collection names: " + selectedCollectionNames +
                         " (IDs: " + selectedCollectionIds +
                         "), binary names: " + selectedBinaryNames +
                         " (IDs: " + selectedBinaryIds +
                         "), threshold: " + threshold +
                         ", debug symbols: " + includeDebugSymbols +
                         ", user submitted debug symbols: " + includeUserSubmittedDebugSymbols);

        // Show progress components and start polling
        taskMonitorComponent.setVisible(true);
        startFunctionMatching();
    }

    /**
     * Called when the Match Functions button is clicked
     */
    private void onMatchButtonClicked() {
        // Trigger function matching based on current filter settings
        filterResults();
    }

    /**
     * Called when the Rename Selected button is clicked
     */
    private void onRenameSelectedButtonClicked() {
        int[] selectedRows = resultsTable.getSelectedRows();
        if (selectedRows.length == 0) {
            showError("Please select one or more rows to rename.");
            return;
        } else {
            hideError();
        }

        // Get the currently displayed results (either filtered or all)
        List<FunctionMatchResult> resultsToShow = filteredFunctionMatchResults.isEmpty() ?
            functionMatchResults : filteredFunctionMatchResults;

        // Get selected matches from the displayed results
        List<FunctionMatchResult> selectedMatches = new ArrayList<>();
        for (int row : selectedRows) {
            if (row < resultsToShow.size()) {
                selectedMatches.add(resultsToShow.get(row));
            }
        }

        // Batch rename selected functions in the portal
        batchRenameFunctions(selectedMatches);

        // Update local function names for selected matches
        importFunctionNames(selectedMatches);
    }

    private void batchRenameFunctions(List<FunctionMatchResult> functionMatches) {
        // Collect all the function matches to rename
        var matches = functionMatches.stream()
                .map(result -> {
                    var func = new FunctionRenameMap();
                    // We are renaming the matcher function, not the matched function!
                    func.setFunctionId(result.matcherFunctionId());
                    func.setNewName(result.bestMatchName());
                    func.setNewMangledName(result.bestMatchMangledName());

                    return func;
                })
                .toList();

        var functionsListRename = new FunctionsListRename();
        functionsListRename.setFunctions(matches);

        try {
            // Rename all functions in one batch call in the portal
            revengService.batchRenameFunctions(functionsListRename);
        } catch (Exception e) {
            showError("Failed to rename functions: " + e.getMessage());
        }
    }

    private void importFunctionNames(List<FunctionMatchResult> functionMatches) {
        var program = programWithBinaryID.program();

        // Retrieve the mangled names map once outside the transaction
        var mangledNameMapOpt = revengService.getFunctionMangledNamesMap(program);

        var functionMap = revengService.getFunctionMap(program);

        program.withTransaction("Apply Function Matching Renames", () -> {
            try {
                var revengMatchNamespace = program.getSymbolTable().getOrCreateNameSpace(
                        program.getGlobalNamespace(),
                        REVENG_AI_NAMESPACE,
                        SourceType.ANALYSIS
                );

                functionMatches.forEach(match -> {
                    var funcID = new FunctionID(match.matcherFunctionId());

                    Function func = functionMap.get(funcID);

                    var revEngMangledName = match.bestMatchMangledName();
                    var revEngDemangledName = match.bestMatchName();

                    if (
                            func != null &&
                                    // Do not override user-defined function names
                                    func.getSymbol().getSource() != SourceType.USER_DEFINED &&
                                    // Exclude thunks and external functions
                                    !func.isThunk() &&
                                    !func.isExternal() &&
                                    // Only accept valid names (no spaces)
                                    !revEngMangledName.contains(" ") &&
                                    !revEngDemangledName.contains(" ")
                    ) {
                        try {
                            func.setName(revEngDemangledName, SourceType.ANALYSIS);
                            func.setParentNamespace(revengMatchNamespace);

                            // Update the mangled name map with the RevEng.AI mangled name
                            mangledNameMapOpt.ifPresent(mangledNameMap -> {
                                try {
                                    mangledNameMap.add(func.getEntryPoint(), revEngMangledName);
                                } catch (Exception e) {
                                    handleError("Failed to update mangled name map for function at " + func.getEntryPoint() + ": " + e.getMessage());
                                }
                            });

                        } catch (Exception e) {
                            handleError("Failed to rename function at " + func.getEntryPoint() + ": " + e.getMessage());
                        }
                    }
                });
            } catch (DuplicateNameException | InvalidInputException e) {
                throw new RuntimeException(e);
            }
        }
        );

        // Show results table after import is complete
        SwingUtilities.invokeLater(this::updateResultsTable);
    }

    @Override
    protected void cancelCallback() {
        stopPolling();
        close();
    }
}
