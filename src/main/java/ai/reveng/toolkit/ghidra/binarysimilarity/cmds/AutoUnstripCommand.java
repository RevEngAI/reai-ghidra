package ai.reveng.toolkit.ghidra.binarysimilarity.cmds;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Command to automatically unstrip a binary using the GhidraRevengService.
 * It requires no interaction and just relies on some defaults
 *
 * To ensure good results it is configured to:
 * - uses low maximum distance by default
 * - uses a high minimum confidence by default
 * - limited to matching against function with debug names
 *
 * TODO: Only match against the official RevEng AI collections
 */
public class AutoUnstripCommand extends BackgroundCommand {
    private final GhidraRevengService revengService;
    private final double maximumDistance;
    private final double minimumConfidence;

    public AutoUnstripCommand(GhidraRevengService revengService) {
        // The default values
        // TODO: Should be made configureable at some point
        this(revengService, 0.1, 90.0);
    }

    public AutoUnstripCommand(GhidraRevengService revengService, double maximumDistance, double minimumConfidence) {
        super("Auto Unstrip", true, true, true);
        this.revengService = revengService;
        this.maximumDistance = maximumDistance;
        this.minimumConfidence = minimumConfidence;
    }


    @Override
    public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
        // TODO: Check that the program has an associated binary ID and that the analysis is finished
        Program program = (Program) obj;
        monitor.setMessage("Searching for Matches");
        monitor.setProgress(0);

        Collection<GhidraFunctionMatchWithSignature> r = revengService.getSimilarFunctionsWithConfidenceAndTypes(
                        program,
                        maximumDistance, // Distance
                        true,
                        true,
                        monitor
                )
                .stream()
                .filter(
                        // Filter to only include matches with more than the minimum confidence
                        match -> match.nameScore().map(b -> b.average() > minimumConfidence).orElse(false)
                )
                .collect(Collectors.toList());

        ApplyMatchesCmd applyMatchesCmd = new ApplyMatchesCmd(revengService, r);
        return applyMatchesCmd.applyTo(program, monitor);

    }
}
