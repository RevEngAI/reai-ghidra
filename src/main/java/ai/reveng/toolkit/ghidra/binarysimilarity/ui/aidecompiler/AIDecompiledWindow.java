package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import ai.reveng.toolkit.ghidra.plugins.ReaiPluginPackage;
import ai.reveng.toolkit.ghidra.core.services.api.types.AIDecompilationStatus;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import java.awt.*;

public class AIDecompiledWindow extends ComponentProviderAdapter {


    private RSyntaxTextArea textArea;
    private RTextScrollPane sp;
    private JTextArea descriptionArea;
    private JComponent component;
    private Function function;

    public AIDecompiledWindow(PluginTool tool, String owner) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "AI Decompiler", owner);
        setIcon(ReaiPluginPackage.REVENG_16);
        component = buildComponent();
    }


    private JComponent buildComponent() {

        component = new JPanel(new BorderLayout());


        descriptionArea = new JTextArea(10, 60);
        descriptionArea.setLineWrap(true);
        descriptionArea.setText("Initial text");
        component.add(descriptionArea, BorderLayout.NORTH);


        textArea = new RSyntaxTextArea(20, 60);
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
        textArea.setEditable(false);
        sp = new RTextScrollPane(textArea);

        component.add(sp, BorderLayout.CENTER);

        return component;
    }

    @Override
    public JComponent getComponent() {
        return component;
    }


    public void setStatus(Function function, AIDecompilationStatus status) {
        setVisible(true);
        this.function = function;
        setCode("Status: " + status);
        if (status.status().equals("success")) {
            setCode(status.decompilation());
            descriptionArea.setText(status.getMarkedUpSummary());
        }
    }

    private void setCode(String code) {
        setVisible(true);
        String text = code;
        textArea.setText(text);
    }

    private void clear() {
        this.function = null;
        setCode("");
        descriptionArea.setText("");
    }

    public void locationChanged(ProgramLocation loc) {
        // If we changed to a different function, we want to clear the output of the old function
        if (function != null && !function.getBody().contains(loc.getAddress())) {
            clear();
        }
    }
}
