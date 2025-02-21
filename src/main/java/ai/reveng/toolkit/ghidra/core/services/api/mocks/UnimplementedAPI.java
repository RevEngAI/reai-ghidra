package ai.reveng.toolkit.ghidra.core.services.api.mocks;

import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;

import javax.script.Bindings;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

public class UnimplementedAPI implements TypedApiInterface {
    @Override
    public List<AnalysisResult> search(BinaryHash hash, String binaryName, Collection collection, AnalysisStatus state) {
        return List.of();
    }

    @Override
    public BinaryID analyse(AnalysisOptionsBuilder binHash) {
        return new BinaryID(1337);
    }

    @Override
    public List<Collection> collectionQuickSearch(ModelName modelName) {
        return List.of();
    }

    @Override
    public List<ModelName> models() {
        return List.of(new ModelName("mock-linux"), new ModelName("mock-linux"));
    }

    @Override
    public List<Collection> collectionQuickSearch(String searchTerm) {
        return List.of();
    }

    @Override
    public String getAnalysisLogs(BinaryID binID) {
        return "";
    }

    @Override
    public void authenticate() throws InvalidAPIInfoException {

    }

    @Override
    public void renameFunctions(Map<FunctionID, String> renameDict) {

    }

    @Override
    public BinaryHash upload(Path binPath) throws FileNotFoundException {
        // Calculate the SHA256 hash of the binary at the path
        try {
            byte[] b = Files.readAllBytes(binPath);
            byte[] hash = MessageDigest.getInstance("SHA256").digest(b);
            return new BinaryHash(HexFormat.of().formatHex(hash));

        } catch (IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public AnalysisID getAnalysisIDfromBinaryID(BinaryID binaryID) {
        return new AnalysisID(1337);
    }
}
