package ai.reveng;

import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardManager;
import ai.reveng.toolkit.ghidra.core.ui.wizard.SetupWizardStateKey;
import ai.reveng.toolkit.ghidra.core.ui.wizard.panels.UserCredentialsPanel;
import docking.wizard.WizardManager;
import docking.wizard.WizardState;
import ghidra.framework.main.FrontEndTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import org.junit.Before;
import org.junit.Test;

import javax.swing.*;

import static org.junit.Assert.assertNull;

public class SetupWizardDialogTest extends AbstractGhidraHeadedIntegrationTest {
    private TestEnv env;
    private FrontEndTool frontEndTool;

    @Before
    public void setUp() throws Exception {
        env = new TestEnv();

        frontEndTool = env.getFrontEndTool();
        env.showFrontEndTool();
    }

    @Test
    public void testWithProd() throws Exception {
        var apiInfo = TestUtils.getApiInfoForTesting();

        SetupWizardManager setupManager = new SetupWizardManager(new WizardState<SetupWizardStateKey>(), frontEndTool
        );
        WizardManager wizardManager = new WizardManager("RevEng.ai Setup Wizard", true, setupManager);
        SwingUtilities.invokeLater(() -> {
                    wizardManager.showWizard(frontEndTool.getToolFrame());
        });
        waitForSwing();
        UserCredentialsPanel p = (UserCredentialsPanel) wizardManager.getCurrentWizardPanel();
        runSwing(() -> {
                    JTextField apiKeyField = (JTextField) getInstanceField("tfApiKey", p);
                    apiKeyField.setText(apiInfo.apiKey());
                    JTextField hostnameField = (JTextField) getInstanceField("tfHostname", p);
                    hostnameField.setText(apiInfo.hostURI().toString());

                    JButton validateButton = (JButton) getInstanceField("validateButton", p);
                    validateButton.doClick();
        });
        waitForSwing();
        var ex = p.getApiInfoException();
        assertNull(ex);
        wizardManager.close();
    }

}
