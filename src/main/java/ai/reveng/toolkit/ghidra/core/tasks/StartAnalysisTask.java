package ai.reveng.toolkit.ghidra.core.tasks;

import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisStatusChangedEvent;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;


/// Task that handles starting an analysis in the Background without blocking the thread that started it
/// (usually the Swing thread)
/// Uploading the binary and registering the analysis can take non-trivial amounts of time, so this
/// requires a dedicated task
///
public class StartAnalysisTask extends Task {

    private final AnalysisOptionsBuilder options;
    private final GhidraRevengService reService;
    private final Program program;
    private final AnalysisLogConsumer log;
    private final PluginTool tool;

    public ProgramWithBinaryID getProgramWithBinaryID() {
        return programWithBinaryID;
    }

    private ProgramWithBinaryID programWithBinaryID;

    public StartAnalysisTask(Program program,
                             AnalysisOptionsBuilder options,
                             GhidraRevengService reService,
                             AnalysisLogConsumer logConsumer,
                             PluginTool tool
    ) {
        super("Running RevEng.AI Analysis", true, false, false);
        this.options = options;
        this.reService = reService;
        this.program = program;
        this.log = logConsumer;
        this.tool = tool;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        monitor.setMessage("Uploading Binary");
        reService.upload(program);
        monitor.setMessage("Exporting Function Boundaries");

        monitor.setMessage("Sending Analysis Request");

        programWithBinaryID = reService.startAnalysis(program, options);

        tool.firePluginEvent(new RevEngAIAnalysisStatusChangedEvent(
                "StartAnalysisTask",
                programWithBinaryID,
                AnalysisStatus.Queued)
        );
    }

    @Override
    public boolean getWaitForTaskCompleted() {
        return super.getWaitForTaskCompleted();
    }
}
