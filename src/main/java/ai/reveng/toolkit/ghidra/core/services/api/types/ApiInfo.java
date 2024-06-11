package ai.reveng.toolkit.ghidra.core.services.api.types;

import ai.reveng.toolkit.ghidra.core.models.ReaiConfig;
import ai.reveng.toolkit.ghidra.core.services.api.TypedApiImplementation;
import com.google.gson.Gson;
import ghidra.util.Msg;
import org.checkerframework.checker.units.qual.A;
import org.json.JSONException;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

public record ApiInfo(
        URI hostURI,
        String apiKey
) {
    public ApiInfo(String hostURI, String apiKey) {
        this(URI.create(hostURI), apiKey);
    }


    public boolean check(){
        return checkServer() && checkCredentials();
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
    public boolean checkCredentials(){
        if (hostURI == null || apiKey == null){
            throw new IllegalArgumentException("hostURI and apiKey must not be null");
        }

        // Send quick health request

        var api = new TypedApiImplementation(this);
        try {
            return api.checkCredentials();
        } catch (JSONException e) {
            throw new IllegalArgumentException("Invalid JSON response from server " + hostURI);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to validate credentials", e);
        }

    }

    public static ApiInfo fromConfig(Path configFilePath) throws FileNotFoundException {
        // Read and parse the config file as JSON
        FileReader reader = new FileReader(configFilePath.toString());
        Gson gson = new Gson();
        ReaiConfig config = gson.fromJson(reader, ReaiConfig.class);
        var apikey = config.getPluginSettings().getApiKey();
        var hostname = config.getPluginSettings().getHostname();
        var modelname = config.getPluginSettings().getModelName();
        return new ApiInfo(hostname, apikey);
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
