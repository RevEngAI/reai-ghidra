package ai.reveng.toolkit.ghidra.core;

import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.listing.Program;

import java.util.Collections;
import java.util.List;

public class Utils {

    public static ModelName getModelNameForProgram(Program program, List<ModelName> models){
        var s = models.stream().map (ModelName::modelName);
        var format = program.getOptions("Program Information").getString("Executable Format", null);
        if (format.equals(ElfLoader.ELF_NAME)){
            s = s.filter(modelName -> modelName.contains("linux"));
        } else if (format.equals(PeLoader.PE_NAME)) {
            s = s.filter(modelName -> modelName.contains("windows"));
        }
        return new ModelName(s.sorted(Collections.reverseOrder()).toList().get(0));
    }
}
