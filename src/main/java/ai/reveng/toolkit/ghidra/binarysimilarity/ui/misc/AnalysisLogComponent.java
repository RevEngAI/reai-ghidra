package ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import generic.theme.GIcon;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorComponent;

import javax.swing.*;

import java.awt.*;

import static ghidra.lifecycle.Unfinished.TODO;

public class AnalysisLogComponent extends ComponentProviderAdapter implements AnalysisLogConsumer {
    private final JTextArea textArea;
    private final JScrollPane scroll;
    private TaskMonitorComponent taskMonitorComponent;
    private final JPanel mainPanel;


    public AnalysisLogComponent(PluginTool tool) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Analysis Log", ReaiPluginPackage.NAME);
        setIcon(ReaiPluginPackage.REVENG_16);

        // Simple text area for now
        textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setText("No logs yet. Use `Check Analysis Status` to fetch them or create a new analysis");

        taskMonitorComponent = new TaskMonitorComponent();
        taskMonitorComponent.setIndeterminate(true);
        taskMonitorComponent.setVisible(false);

        scroll = new JScrollPane(textArea);
        
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(scroll, BorderLayout.CENTER);
        mainPanel.add(taskMonitorComponent, BorderLayout.SOUTH);
    }

//    private void refreshLog() {
//        var api = tool.getService(GhidraRevengService.class);
//        textArea.setText(api.getAnalysisLog(new AnalysisID(173939)));
//    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    public void setLogs(String logs) {
        textArea.setText(logs);
        JScrollBar vertical = scroll.getVerticalScrollBar();
        vertical.setValue( vertical.getMaximum() );
    }

    public TaskMonitor getTaskMonitor() {
        taskMonitorComponent.setVisible(true);
        return taskMonitorComponent;
    }

    public void analysisFinished() {
        taskMonitorComponent.setVisible(false);
    }

    @Override
    public void consumeLogs(String logs) {
        this.setLogs(logs);
    }
}
