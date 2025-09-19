import ai.reveng.toolkit.ghidra.binarysimilarity.cmds.AutoUnstripCommand;
import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.GhidraRevengService;
import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;
import ai.reveng.toolkit.ghidra.core.services.api.types.BinaryID;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import static ai.reveng.toolkit.ghidra.binarysimilarity.BinarySimilarityPlugin.REVENG_AI_NAMESPACE;

public class RevEngAutoRenamePostScript extends GhidraScript {
    @Override
    protected void run() throws Exception {
        // Services are not available in headless mode, so we have to instantiate it ourselves
        var ghidraRevengService = new GhidraRevengService(ApiInfo.fromConfig());

        ghidraRevengService.upload(currentProgram);

        AnalysisOptionsBuilder options = AnalysisOptionsBuilder.forProgram(currentProgram);
        var binID = ghidraRevengService.analyse(currentProgram, options, monitor, null);
        // Wait for analysis to finish
        ghidraRevengService.waitForFinishedAnalysis(monitor, binID, null);

        new AutoUnstripCommand(ghidraRevengService).applyTo(currentProgram);

        var revengMatchNamespace = currentProgram.getSymbolTable().getOrCreateNameSpace(
                currentProgram.getGlobalNamespace(),
                REVENG_AI_NAMESPACE,
                SourceType.ANALYSIS
        );
        // Fetch Function matches
        ghidraRevengService.getSimilarFunctions(currentProgram, 1, 0.05, true).forEach(
                (function, matches) -> {
                    var bestMatch = matches.get(0);
                    Namespace libraryNamespace = null;
                    try {
                        libraryNamespace = currentProgram.getSymbolTable().getOrCreateNameSpace(
                                revengMatchNamespace,
                                bestMatch.nearest_neighbor_binary_name(),
                                SourceType.ANALYSIS);
                    } catch (DuplicateNameException e) {
                        throw new RuntimeException(e);
                    } catch (InvalidInputException e) {
                        throw new RuntimeException(e);
                    }
                    try {
                        function.getSymbol().setNameAndNamespace(
                                bestMatch.nearest_neighbor_function_name(),
                                libraryNamespace,
                                SourceType.ANALYSIS
                        );
                        println("Renamed " + function.getName() + " to " + bestMatch.nearest_neighbor_function_name() + " from " + bestMatch.nearest_neighbor_binary_name() + " with similarity " + bestMatch.similarity());
                    } catch (DuplicateNameException e) {
                        throw new RuntimeException(e);
                    } catch (InvalidInputException e) {
                        throw new RuntimeException(e);
                    } catch (CircularDependencyException e) {
                        throw new RuntimeException(e);
                    }

                }

        );



    }


    private void waitForAnalysis(GhidraRevengService ghidraRevengService, BinaryID binID) throws InterruptedException {
        var analysisComplete = false;
        while (!analysisComplete) {
            Thread.sleep(5000);
            switch (ghidraRevengService.pollStatus(binID)) {
                case Complete:
                    println("Analysis finished successfully");
                    analysisComplete = true;
                    break;
                case Error:
                    println("Analysis failed");
                    analysisComplete = true;
                    break;
                case Processing:
                    println("Analysis still running");
                    break;
                case Queued:
                    println("Analysis queued");
                    break;
                default:
                    println("Unknown status");
                    break;
            }
        }
    }
}
