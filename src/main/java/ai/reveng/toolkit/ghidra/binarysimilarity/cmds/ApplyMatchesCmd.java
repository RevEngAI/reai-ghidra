package ai.reveng.toolkit.ghidra.binarysimilarity.cmds;

import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.Collection;

// We can't use BackgroundCommand<Program> because that breaks compatibility with Ghidra 11.0
public class ApplyMatchesCmd extends BackgroundCommand {
    private final Collection<GhidraFunctionMatchWithSignature> matches;

    public ApplyMatchesCmd(Collection<GhidraFunctionMatchWithSignature> matches) {
        super("Apply Matches", true, true, true);
        this.matches = matches;
    }
    @Override
    public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
        if (!(obj instanceof Program)) {
            throw new IllegalArgumentException("This command can only be applied to a Ghidra Program");
        }
        Program program = (Program) obj;
        var tID = program.startTransaction("RevEng.AI: Apply Matches");
        for (GhidraFunctionMatchWithSignature match : matches) {
            new ApplyMatchCmd(match).applyTo(program);
        }
        program.endTransaction(tID, true);
        return true;
    }
}
