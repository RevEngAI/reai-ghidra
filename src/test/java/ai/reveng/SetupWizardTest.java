package ai.reveng;

import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardManager;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import ai.reveng.toolkit.ghidra.core.ui.wizard.panels.UserCredentialsPanel;
import docking.wizard.WizardManager;
import docking.wizard.WizardState;
import org.junit.Test;

public class SetupWizardTest extends RevEngMockableHeadedIntegrationTest {
    @Test
    public void testUserCredentialsPanel() throws Exception {
        var tool = env.getTool();

        var wizardState = new WizardState<SetupWizardStateKey>();
        wizardState.put(SetupWizardStateKey.API_KEY, "my-api-key");
        SetupWizardManager setupManager = new SetupWizardManager(wizardState, tool);
        WizardManager wizardManager = new WizardManager("RevEng.AI: Configuration", true, setupManager);
        runSwing(() -> wizardManager.showWizard(tool.getToolFrame()), false);
        var dialog = waitForDialogComponent("RevEng.AI: Configuration");

        waitForSwing();
        capture(dialog.getComponent(), "configuration-window");
    }
}
