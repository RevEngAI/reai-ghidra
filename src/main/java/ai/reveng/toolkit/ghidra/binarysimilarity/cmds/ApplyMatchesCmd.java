package ai.reveng.toolkit.ghidra.binarysimilarity.cmds;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.FunctionID;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.jetbrains.annotations.NotNull;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

// We can't use BackgroundCommand<Program> because that breaks compatibility with Ghidra 11.0
public class ApplyMatchesCmd extends BackgroundCommand {
    private final Collection<GhidraFunctionMatchWithSignature> matches;
    private final GhidraRevengService service;

    public ApplyMatchesCmd(@NotNull GhidraRevengService service, Collection<GhidraFunctionMatchWithSignature> matches) {
        super("Apply Matches", true, true, true);
        this.matches = matches;
        this.service = service;
    }
    @Override
    public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
        if (!(obj instanceof Program)) {
            throw new IllegalArgumentException("This command can only be applied to a Ghidra Program");
        }
        Program program = (Program) obj;
        var tID = program.startTransaction("RevEng.AI: Apply Matches");
        for (GhidraFunctionMatchWithSignature match : matches) {
            // Pass null for the service because we are going to handle the renaming as a batch
            new ApplyMatchCmd(null, match).applyTo(program);
        }

        Map<FunctionID, String> renameDict = matches.stream().collect(Collectors.toMap(
                match -> match.functionMatch().origin_function_id(),
                match -> match.functionMatch().name()
        ));
        service.getApi().renameFunctions(renameDict);
        program.endTransaction(tID, true);
        return true;
    }
}
