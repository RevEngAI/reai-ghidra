package ai.reveng.toolkit.ghidra.binarysimilarity.ui.dialog;

import docking.DialogComponentProvider;
import docking.widgets.label.GDLabel;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;

public class RevEngDialogComponentProvider extends DialogComponentProvider  {
    public RevEngDialogComponentProvider(String title, boolean isModal) {
        super(title, isModal);
    }

    protected JPanel createTitlePanel(String title) {
        // Load icon from resources
        Icon dialogIcon = null;
        try {
            dialogIcon = ResourceManager.loadImage("images/icon_50.png");
        } catch (Exception e) {
            // If loading fails, fall back to no icon
        }

        // Create title label
        JLabel titleLabel = new GDLabel(title);
        // Make the title text bold
        Font currentFont = titleLabel.getFont();
        titleLabel.setFont(currentFont.deriveFont(Font.BOLD));

        JPanel titlePanel = new JPanel(new BorderLayout());
        titlePanel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        // Add icon to the left if available
        if (dialogIcon != null) {
            JLabel iconLabel = new JLabel(dialogIcon);
            titlePanel.add(iconLabel, BorderLayout.WEST);
        }

        // Create a centered panel for the title text
        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.X_AXIS));
        centerPanel.add(Box.createHorizontalGlue());
        centerPanel.add(titleLabel);
        centerPanel.add(Box.createHorizontalGlue());

        titlePanel.add(centerPanel, BorderLayout.CENTER);

        return titlePanel;
    }
}