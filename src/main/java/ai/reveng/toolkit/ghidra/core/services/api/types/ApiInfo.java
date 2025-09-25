package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.models.ReaiConfig;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiImplementation;
import ai.reveng.toolkit.ghidra.core.services.api.types.exceptions.InvalidAPIInfoException;
import com.google.gson.Gson;
import org.json.JSONException;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;

public record ApiInfo(
        URI hostURI,
        URI portalURI,
        String apiKey
) {
    public ApiInfo(String hostURI, String portalURI, String apiKey) {
        this(URI.create(hostURI), URI.create(portalURI), apiKey);
    }

    public boolean checkServer(){
        var api = new TypedApiImplementation(this);
        try {
            api.health();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    public void checkCredentials() throws InvalidAPIInfoException {
        if (hostURI == null || apiKey == null){
            throw new InvalidAPIInfoException("hostURI and apiKey must not be null");
        }
        var api = new TypedApiImplementation(this);

        // Send quick health request
        var health = api.health();
        if (!health.getBoolean("success")){
            throw new InvalidAPIInfoException("Server health check failed: " + health.getString("message"));
        }

        // Throws InvalidAPIInfoException if authentication fails
        api.authenticate();

    }

    public static ApiInfo fromConfig(Path configFilePath) throws FileNotFoundException {
        // Read and parse the config file as JSON
        FileReader reader = new FileReader(configFilePath.toString());
        Gson gson = new Gson();
        ReaiConfig config = gson.fromJson(reader, ReaiConfig.class);
        var apikey = config.getPluginSettings().getApiKey();
        var hostname = config.getPluginSettings().getHostname();
        var portalHostname = config.getPluginSettings().getPortalHostname();
        return new ApiInfo(hostname, portalHostname, apikey);
    }

    public static ApiInfo fromConfig() throws FileNotFoundException {
        String uHome = System.getProperty("user.home");
        String cDir = ".reai";
        String cFileName = "reai.json";
        Path configDirPath = Paths.get(uHome, cDir);
        Path configFilePath = configDirPath.resolve(cFileName);

        return fromConfig(configFilePath);

    }
}
