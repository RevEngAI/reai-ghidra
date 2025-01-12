package ai.reveng.toolkit.ghidra.core.services.api.types.binsync;

import ghidra.program.model.data.CategoryPath;

public record TypePathAndName(
        String name,
        String[] path
) {

    public static TypePathAndName fromString(String str){
        String[] parts = str.split("/");
        String name = parts[parts.length - 1];
        String[] path = new String[parts.length - 1];
        System.arraycopy(parts, 0, path, 0, parts.length - 1);
        return new TypePathAndName(name, path);
    }

    public CategoryPath toCategoryPath(){
        return new CategoryPath(CategoryPath.ROOT, path);
    }

}
