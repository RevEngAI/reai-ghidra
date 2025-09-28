package ai.reveng.toolkit.ghidra.core;

import ai.reveng.toolkit.ghidra.core.services.api.types.AnalysisStatus;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;
import ai.reveng.toolkit.ghidra.core.types.ProgramWithBinaryID;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.program.model.listing.Program;

/**
 * Event that is fired when a RevEng.AI analysis result with some program changes.
 * This includes the initial event when a binary ID is associated with a program
 * There are various scenarios when this happens:
 * <ul>
 * <li>An analysis has just been started and associated with the program via an analysis ID</li>
 * <li>The plugin was just loaded, and it contained a stored binary ID pointing to an existing analysis</li>
 * <li>An analysis has just finished in the backend</li>
 * </ul>
 *
 * This should _not_ be used to indicate that the results of an analysis have been loaded into the program
 * (e.g. function info). Use {@link ai.reveng.toolkit.ghidra.core.RevEngAIAnalysisResultsLoaded} for that.
 */
public class RevEngAIAnalysisStatusChangedEvent extends PluginEvent {
    private final AnalysisStatus status;
    private final ProgramWithBinaryID programWithBinaryID;

    public RevEngAIAnalysisStatusChangedEvent(String sourceName, ProgramWithBinaryID programWithBinaryID, AnalysisStatus status) {
        super(sourceName, "RevEngAI Analysis Finished");
        if (status == null || programWithBinaryID == null) {
            throw new IllegalArgumentException("args cannot be null");
        }
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

    @Override
    public String toString() {
        return "RevEngAIAnalysisStatusChangedEvent{" +
                "status=" + status +
                ", programWithBinaryID=" + programWithBinaryID +
                '}';
    }
}
