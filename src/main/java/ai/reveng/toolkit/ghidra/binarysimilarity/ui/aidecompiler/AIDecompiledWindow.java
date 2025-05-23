package ai.reveng.toolkit.ghidra.binarysimilarity.ui.aidecompiler;

import ai.reveng.toolkit.ghidra.ReaiPluginPackage;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;

public class AIDecompiledWindow extends ComponentProviderAdapter {


    private RSyntaxTextArea textArea;
    private RTextScrollPane sp;
    public AIDecompiledWindow(PluginTool tool, String owner) {
        super(tool, ReaiPluginPackage.WINDOW_PREFIX + "AI Decompiler", owner);
        setIcon(ReaiPluginPackage.REVENG_16);
        textArea = buildComponent();
    }


    private RSyntaxTextArea buildComponent(){
        textArea = new RSyntaxTextArea(20, 60);
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_C);
        textArea.setEditable(false);
        sp = new RTextScrollPane(textArea);
        return textArea;
    }



    public void setCode(String code){
        setVisible(true);
        String text = code;
        textArea.setText(text);
    }

    @Override
    public JComponent getComponent() {
        return sp;
    }

    public void setStatus(String status) {
        setVisible(true);
        setCode("Status: " + status);
    }
}
