package ai.reveng.toolkit.ghidra.binarysimilarity.cmds;

import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.GhidraFunctionMatchWithSignature;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;


import static ai.reveng.toolkit.ghidra.plugins.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;

// We can't use Command<Program> because that breaks compatibility with Ghidra 11.0
public class ApplyMatchCmd implements Command {

    private final Program program;
    private final GhidraFunctionMatchWithSignature match;
    @Nullable private final GhidraRevengService service;

    public ApplyMatchCmd(
            @Nullable GhidraRevengService service,
            @NotNull GhidraFunctionMatchWithSignature match) {
        super();
        this.program = match.function().getProgram();
        this.match = match;
        this.service = service;
    }
    @Override
    public boolean applyTo(DomainObject obj) {
        // Check that this is the same program
        if (obj != this.program) {
            throw new IllegalArgumentException("This command can only be applied to the same program as the one provided in the constructor");
        }
        var libraryNamespace = getLibraryNameSpaceForName(match.functionMatch().nearest_neighbor_binary_name());
        var function = match.function();
        try {
            function.setParentNamespace(libraryNamespace);
        } catch (DuplicateNameException e) {
            throw new RuntimeException(e);
        } catch (InvalidInputException e) {
            throw new RuntimeException(e);
        } catch (CircularDependencyException e) {
            throw new RuntimeException(e);
        }

        FunctionDefinitionDataType signature = null;
        if (match.signature().isPresent()) {
            try {
                signature = GhidraRevengService.getFunctionSignature(match.signature().get());
            } catch (DataTypeDependencyException e) {
                Msg.showError(this, null,"Failed to create function signature",
                        "Failed to create signature for match function with type %s"
                                .formatted(match.signature().get().func_types().getSignature()),
                        e);
            }
        }

        if (signature != null) {
            var cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(), signature, SourceType.USER_DEFINED);
            cmd.applyTo(program);
        }
        else {
            var renameCmd = new RenameLabelCmd(match.function().getSymbol(), match.functionMatch().name(), SourceType.USER_DEFINED);
            renameCmd.applyTo(program);
        }
        // If we have a service then push the name. If not then it was explicitly not provided, i.e. the caller
        // is responsible for pushing the names in batch
        if (service != null) {
            service.getApi().renameFunction(match.functionMatch().origin_function_id(), match.functionMatch().name());
        }


        return false;
    }

    public void applyWithTransaction() {
        var tID = program.startTransaction("RevEng.AI: Apply Match");
        var status = applyTo(program);
        program.endTransaction(tID, status);
    }

    private Namespace getRevEngAINameSpace() {
        Namespace revengMatchNamespace = null;
        try {
            revengMatchNamespace = program.getSymbolTable().getOrCreateNameSpace(
                    program.getGlobalNamespace(),
                    REVENG_AI_NAMESPACE,
                    SourceType.ANALYSIS
            );
        } catch (DuplicateNameException | InvalidInputException e) {
            throw new RuntimeException(e);
        }
        return revengMatchNamespace;
    }

    private Namespace getLibraryNameSpaceForName(String name) {
        Namespace libraryNamespace = null;
        try {
            libraryNamespace = program.getSymbolTable().getOrCreateNameSpace(
                    getRevEngAINameSpace(),
                    name,
                    SourceType.USER_DEFINED);
        } catch (DuplicateNameException | InvalidInputException e) {
            throw new RuntimeException(e);
        }
        return libraryNamespace;
    }

    @Override
    public String getStatusMsg() {
        return "";
    }

    @Override
    public String getName() {
        return "";
    }
}
