package ai.reveng.toolkit.ghidra.binarysimilarity.ui.misc;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import generic.theme.GIcon;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

import javax.swing.*;

import static ghidra.lifecycle.Unfinished.TODO;

public class AnalysisLogComponent extends ComponentProviderAdapter {
    private final JTextArea textArea;
    private final DockingAction refreshLogAction;
    private final JScrollPane scroll;

    public AnalysisLogComponent(PluginTool tool) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "Analysis Log", ReaiPluginPackage.NAME);
        setIcon(ReaiPluginPackage.REVENG_16);

        // Simple text area for now
        textArea = new JTextArea();
        textArea.setEditable(false);

        scroll = new JScrollPane(textArea);

        refreshLogAction = new ActionBuilder("Refresh Log", getOwner())
                .toolBarIcon(new GIcon("icon.search"))
                .menuPath("Refresh Log")
                .description("Refresh the analysis log")
                .enabledWhen(ac -> true)
                .onAction(ac -> TODO())
                .buildAndInstallLocal(this);

    }

//    private void refreshLog() {
//        var api = tool.getService(GhidraRevengService.class);
//        textArea.setText(api.getAnalysisLog(new AnalysisID(173939)));
//    }

    @Override
    public JComponent getComponent() {
        return scroll;
    }

    public void setLogs(String logs) {
        textArea.setText(logs);
        JScrollBar vertical = scroll.getVerticalScrollBar();
        vertical.setValue( vertical.getMaximum() );
    }
}
