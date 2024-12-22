package ai.reveng.toolkit.ghidra.core;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;
import ai.reveng.toolkit.ghidra.core.services.api.types.ProgramWithBinaryID;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;

/**
 * Event that is fired when a RevEng.AI analysis result with some program changes.
 * This includes the initial event when a binary ID is associated with a program
 * There are various scenarios when this happens:
 * - A analysis has just been associated with the program
 * - The plugin was just loaded, and it contained a stored binary ID pointing to an existing analysis
 */
public class RevEngAIAnalysisStatusChanged extends PluginEvent {
    private final AnalysisStatus status;
    private final ProgramWithBinaryID programWithBinaryID;

    public RevEngAIAnalysisStatusChanged(String sourceName, ProgramWithBinaryID programWithBinaryID, AnalysisStatus status) {
        super(sourceName, "RevEngAI Analysis Finished");
        this.status = status;
        this.programWithBinaryID = programWithBinaryID;
    }

    public AnalysisStatus getStatus() {
        return status;
    }

    public ProgramWithBinaryID getProgramWithBinaryID() {
        return programWithBinaryID;
    }

    public Program getProgram() {
        return programWithBinaryID.program();
    }

    public BinaryID getBinaryID() {
        return programWithBinaryID.binaryID();
    }
}
