package ai.reveng.toolkit.ghidra.core.tasks;

import ai.reveng.toolkit.ghidra.core.AnalysisLogConsumer;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;


public class AnalysisTask extends Task {

    private final AnalysisOptionsBuilder options;
    private final GhidraRevengService reService;
    private final Program program;
    private final AnalysisLogConsumer log;
    private AnalysisStatus finalAnalysisStatus;

    public ProgramWithBinaryID getProgramWithBinaryID() {
        return programWithBinaryID;
    }

    public AnalysisStatus getFinalAnalysisStatus() {
        return finalAnalysisStatus;
    }

    private ProgramWithBinaryID programWithBinaryID;

    public AnalysisTask(Program program,
                        AnalysisOptionsBuilder options,
                        GhidraRevengService reService,
                        AnalysisLogConsumer logConsumer
    ) {
        super("Running RevEng.AI Analysis", true, false, false);
        this.options = options;
        this.reService = reService;
        this.program = program;
        this.log = logConsumer;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
        monitor.setMessage("Uploading Binary");
        reService.upload(program);
        monitor.setMessage("Exporting Function Boundaries");

        monitor.setMessage("Sending Analysis Request");

        programWithBinaryID = reService.startAnalysis(program, options);
        monitor.setMessage("Waiting for Analysis to finish");
        finalAnalysisStatus = reService.waitForFinishedAnalysis(monitor, programWithBinaryID, log);
    }

    @Override
    public boolean getWaitForTaskCompleted() {
        return super.getWaitForTaskCompleted();
    }
}
