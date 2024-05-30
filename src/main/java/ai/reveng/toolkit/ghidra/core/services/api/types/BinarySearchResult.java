package ai.reveng.toolkit.ghidra.core.services.api.types;


import org.json.JSONObject;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
Very similar to an {@link AnalysisResult} but not quite the same
 */
public record BinarySearchResult(
    String owner,
    String model_name,
    BinaryHash sha_256_hash,
    BinaryID binary_id,
    String binary_name,
    Date creation,
    int model_id,
    AnalysisStatus status)
{
    static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'hh:mm:ss.SSSSSS");
    public static BinarySearchResult fromJSONObject(JSONObject json) {
        Date creationTime;
        try {
            creationTime = dateFormat.parse(json.getString("creation"));
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        return new BinarySearchResult(
                json.getString("owner"),
                json.getString("model_name"),
                new BinaryHash(json.getString("sha_256_hash")),
                new BinaryID(json.getInt("binary_id")),
                json.getString("binary_name"),
                creationTime,
                json.getInt("model_id"),
                AnalysisStatus.valueOf(json.getString("status"))
        );
    }
}
