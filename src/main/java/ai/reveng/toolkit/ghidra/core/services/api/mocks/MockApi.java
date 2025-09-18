package ai.reveng.toolkit.ghidra.core.services.api.mocks;

import ai.reveng.toolkit.ghidra.core.services.api.AnalysisOptionsBuilder;
import ai.reveng.toolkit.ghidra.core.services.api.ModelName;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiInterface;
import ai.reveng.toolkit.ghidra.core.services.api.types.*;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.APIAuthenticationException;
import org.json.JSONObject;

import javax.annotation.Nullable;
import java.io.FileNotFoundException;
import java.math.BigDecimal;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class MockApi implements TypedApiInterface {
    @Override
    public BinaryHash upload(Path binPath) throws FileNotFoundException {
        return new BinaryHash("b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6");
    }

    @Override
    public Object delete(BinaryID binID) {
        return TypedApiInterface.super.delete(binID);
    }

    @Override
    public List<LegacyAnalysisResult> recentAnalyses() {
        return TypedApiInterface.super.recentAnalyses();
    }

    @Override
    public List<LegacyAnalysisResult> search(BinaryHash hash) {
        if (hash.equals(new BinaryHash("b04c1259718dd16c0ffbd0931aeecf07746775cc2f1cda76e46d51af165f3ba6"))) {
            return List.of(new LegacyAnalysisResult(
                    new BinaryID(17920),
                    "true",
                    "no creation date",
                    1,
                    "model name",
                    hash,
                    AnalysisStatus.Complete,
                    123456,
                    "b48f61e85bcbc7866d78a8f0b72acd8c0c177ebd15cea466d1edb67409fca269"
            ));
        }
        return List.of();
    }

    @Override
    public List<FunctionMatch> annSymbolsForFunctions(List<FunctionID> fID, int resultsPerFunction, @Nullable List<CollectionID> collections, @Nullable List<AnalysisID> analysisIDs, double distance, boolean debug) {
       var r = """
               {
                 "success": true,
                 "settings": {
                   "result_per_function": 3,
                   "debug_mode": false,
                   "distance": 0.1
                 },
                 "function_matches": {
                   "3524066": {
                     "3524714": {
                       "function_name": "deregister_tm_clones",
                       "binary_name": "x86-64_mbedtls_mbedtls-3.0.0_libmbedtls.so.3.0.0_O0_b4aa90e12844e4c3d6148d3f66dcf2acc9ee8bc3badc791036a6a251b8becfa0",
                       "binary_id": 17939,
                       "sha_256_hash": "b4aa90e12844e4c3d6148d3f66dcf2acc9ee8bc3badc791036a6a251b8becfa0",
                       "confidence": 1.0
                     },
                     "3521948": {
                       "function_name": "deregister_tm_clones",
                       "binary_name": "x86-64_mbedtls_mbedtls-3.0.0_libmbedtls.so.3.0.0_O0_b4aa90e12844e4c3d6148d3f66dcf2acc9ee8bc3badc791036a6a251b8becfa0",
                       "binary_id": 17908,
                       "sha_256_hash": "b4aa90e12844e4c3d6148d3f66dcf2acc9ee8bc3badc791036a6a251b8becfa0",
                       "confidence": 1.0
                     }
                   }
                 }
               }
               """;
        var jsonObject = new JSONObject(r);
        var result = new ArrayList<FunctionMatch>();
        for (Map.Entry<String, Object> entry : jsonObject.getJSONObject("function_matches").toMap().entrySet()) {
            String originFunctionIDKey = entry.getKey();
            FunctionID originFunctionID = new FunctionID(Integer.parseInt(originFunctionIDKey));
            Object map = entry.getValue();
            Map<String, Object> matches = (Map<String, Object>) map;
            for (Map.Entry<String, Object> matchEntry : matches.entrySet()) {
                String matchedFunctionID = matchEntry.getKey();
                Map<String, Object> matchInfo = (Map<String, Object>) matchEntry.getValue();

                double similarity = ((BigDecimal) matchInfo.get("confidence")).doubleValue();
                FunctionID neighbourFunctionID = new FunctionID(Integer.parseInt(matchedFunctionID));
                BinaryID neighbourBinaryID = new BinaryID((int) matchInfo.get("binary_id"));
                FunctionMatch match = new FunctionMatch(
                        originFunctionID,
                        neighbourFunctionID,
                        (String) matchInfo.get("function_name"),
                        (String) matchInfo.get("binary_name"),
                        new BinaryHash((String) matchInfo.get("sha_256_hash")),
                        neighbourBinaryID,
                        false,
                        similarity
                        );
                result.add(match);
            }
        }
        return result;
    }

    @Override
    public AnalysisStatus status(BinaryID binID) {
        return AnalysisStatus.Complete;
    }

    @Override
    public BinaryID analyse(AnalysisOptionsBuilder binHash) {
        return new BinaryID(17920);
    }

    @Override
    public List<FunctionMatch> annSymbolsForBinary(BinaryID binID, int resultsPerFunction, double distance, boolean debugMode, List<Collection> collections) {
        var r = """
                {
                  "success": true,
                  "settings": {
                    "result_per_function": 5,
                    "debug_mode": false,
                    "distance": 0.1
                  },
                  "function_matches": [
                    {
                      "origin_function_id": 3524066,
                      "nearest_neighbor_id": 3516862,
                      "nearest_neighbor_function_name": "deregister_tm_clones",
                      "nearest_neighbor_binary_name": "x86-64_libsodium_1.0.19_libsodium.so.26.1.0_O3_15786002d4e406781b138cae220192ecbd9ef6e3e9f795e3ed3b0011c087d86b",
                      "nearest_neighbor_sha_256_hash": "15786002d4e406781b138cae220192ecbd9ef6e3e9f795e3ed3b0011c087d86b",
                      "nearest_neighbor_binary_id": 17882,
                      "nearest_neighbor_debug": true,
                      "confidence": 0.9175930397537833
                    },
                    {
                      "origin_function_id": 3524066,
                      "nearest_neighbor_id": 3506882,
                      "nearest_neighbor_function_name": "deregister_tm_clones",
                      "nearest_neighbor_binary_name": "0001875fddded34615d69e2153f4f2216ea31c5c16c73aba05ae85bcf8256f29",
                      "nearest_neighbor_sha_256_hash": "0001875fddded34615d69e2153f4f2216ea31c5c16c73aba05ae85bcf8256f29",
                      "nearest_neighbor_binary_id": 17867,
                      "nearest_neighbor_debug": true,
                      "confidence": 0.9059488839050542
                    }
                  ]
                }
                """;
        var jsonObject = new JSONObject(r);
        var result = new ArrayList<FunctionMatch>();
        jsonObject.getJSONArray("function_matches").forEach((Object o) -> {
            result.add(FunctionMatch.fromJSONObject((JSONObject) o));
        });
        return result;
    }

    @Override
    public boolean healthStatus() {
        return true;
    }

    @Override
    public String healthMessage() {
        return "Mock Health Message";
    }

    @Override
    public String getAnalysisLogs(AnalysisID analysisID) {
        return "";
    }

    @Override
    public void authenticate() throws APIAuthenticationException {
    }

    @Override
    public void renameFunctions(Map<FunctionID, String> renameDict) {

    }

    @Override
    public void renameFunction(FunctionID id, String newName) {
        
    }

    @Override
    public List<ModelName> models() {
        return null;
    }


    @Override
    public List<FunctionInfo> getFunctionInfo(BinaryID binaryID) {
        var r = """
                {
                  "success": true,
                  "functions": [
                    {
                      "function_id": 3524063,
                      "function_name": "_DT_INIT",
                      "function_vaddr": 4096,
                      "function_size": 26
                    },
                    {
                      "function_id": 3524064,
                      "function_name": "FUN_00001030",
                      "function_vaddr": 4144,
                      "function_size": 1403
                    },
                    {
                      "function_id": 3524065,
                      "function_name": "entry",
                      "function_vaddr": 5552,
                      "function_size": 37
                    },
                    {
                      "function_id": 3524066,
                      "function_name": "FUN_000015e0",
                      "function_vaddr": 5600,
                      "function_size": 32
                    },
                    {
                      "function_id": 3524067,
                      "function_name": "FUN_00001610",
                      "function_vaddr": 5648,
                      "function_size": 49
                    },
                    {
                      "function_id": 3524068,
                      "function_name": "_FINI_0",
                      "function_vaddr": 5712,
                      "function_size": 53
                    },
                    {
                      "function_id": 3524069,
                      "function_name": "FUN_000016b0",
                      "function_vaddr": 5808,
                      "function_size": 222
                    },
                    {
                      "function_id": 3524070,
                      "function_name": "FUN_000017b0",
                      "function_vaddr": 6064,
                      "function_size": 231
                    },
                    {
                      "function_id": 3524071,
                      "function_name": "FUN_000018a0",
                      "function_vaddr": 6304,
                      "function_size": 54
                    },
                    {
                      "function_id": 3524072,
                      "function_name": "FUN_000018e0",
                      "function_vaddr": 6368,
                      "function_size": 248
                    },
                    {
                      "function_id": 3524073,
                      "function_name": "FUN_00001a00",
                      "function_vaddr": 6656,
                      "function_size": 86
                    },
                    {
                      "function_id": 3524074,
                      "function_name": "FUN_00001a60",
                      "function_vaddr": 6752,
                      "function_size": 241
                    },
                    {
                      "function_id": 3524075,
                      "function_name": "FUN_00001b70",
                      "function_vaddr": 7024,
                      "function_size": 5613
                    },
                    {
                      "function_id": 3524076,
                      "function_name": "FUN_000031f0",
                      "function_vaddr": 12784,
                      "function_size": 118
                    },
                    {
                      "function_id": 3524077,
                      "function_name": "FUN_00003280",
                      "function_vaddr": 12928,
                      "function_size": 1497
                    },
                    {
                      "function_id": 3524078,
                      "function_name": "FUN_00003860",
                      "function_vaddr": 14432,
                      "function_size": 18
                    }
                  ]
                }
                """;
        var jsonObject = new JSONObject(r);
        var result = new ArrayList<FunctionInfo>();
        jsonObject.getJSONArray("functions").forEach((Object o) -> {
            result.add(FunctionInfo.fromJSONObject((JSONObject) o));
        });
        return result;
    }
}
