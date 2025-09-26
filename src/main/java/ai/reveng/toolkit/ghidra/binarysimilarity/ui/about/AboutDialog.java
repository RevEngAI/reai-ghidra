package ai.reveng.toolkit.ghidra.binarysimilarity.ui.about;

import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Shows a dialog with about information.
 */
public class AboutDialog extends DialogComponentProvider {
    private final PluginTool tool;

    public AboutDialog(PluginTool tool) {
        super(ReaiPluginPackage.WINDOW_PREFIX + "About", true);
        this.tool = tool;

        buildInterface(getPluginVersion());
        setPreferredSize(300, 160);
    }

    private String getPluginVersion() {
        String pluginVersion = "unknown";
        try {
            // This file comes from the release.yml running in the CI
            var inputStream = ResourceManager.getResourceAsStream("reai_ghidra_plugin_version.txt");
            pluginVersion = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).trim();
            inputStream.close();
        } catch (IOException e) {

        }

        return pluginVersion;
    }

    private void buildInterface(String pluginVersion) {
        JPanel mainPanel = new JPanel();
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Create the about content
        JPanel contentPanel = createAboutContent(pluginVersion);

        // Make it scrollable
        JScrollPane scrollPane = new JScrollPane(contentPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setBorder(null);

        mainPanel.add(scrollPane, BorderLayout.CENTER);

        addWorkPanel(mainPanel);
        addDismissButton();
    }

    private JPanel createAboutContent(String pluginVersion) {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 5));

        JLabel label = new JLabel("RevEng.AI Ghidra Plugin: " + pluginVersion);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);

        // MenuBar section
        panel.add(label);
        panel.add(Box.createVerticalStrut(10));

        return panel;
    }
}
