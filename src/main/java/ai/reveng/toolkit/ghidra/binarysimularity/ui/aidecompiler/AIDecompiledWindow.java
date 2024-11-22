package ai.reveng.toolkit.ghidra.binarysimularity.ui.aidecompiler;

import docking.Tool;
import generic.theme.GColor;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;

import javax.swing.*;

public class AIDecompiledWindow extends ComponentProviderAdapter {


    private final RSyntaxTextArea editorPane;
    public AIDecompiledWindow(PluginTool tool, String owner) {
        super(tool, "AI Decompiler", owner);
        editorPane = buildComponent();
    }


    private RSyntaxTextArea buildComponent(){
        var textArea = new RSyntaxTextArea(20, 60);
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
        textArea.setEditable(false);
        return textArea;
    }



    public void setCode(String code){
        setVisible(true);
        String text = code;
        editorPane.setText(text);
    }

    @Override
    public JComponent getComponent() {
        return editorPane;
    }

    public void setStatus(String status) {
        setVisible(true);
        setCode("Status: " + status);
    }
}
