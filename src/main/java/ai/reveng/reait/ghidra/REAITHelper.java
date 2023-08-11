package ai.reveng.reait.ghidra;

import java.io.File;

import ai.reveng.reait.client.Client;
import ghidra.program.flatapi.FlatProgramAPI;

/**
 * Helper class that contains common objects that are useful across components
 */
public final class REAITHelper {
	private static REAITHelper instance;
	
	/// API client for sending and receiving requests
	private Client client;
	/// Provides access to the Ghidra FlatAPI for easy wrappers
	private FlatProgramAPI flatAPI;
	/// SHA3-256 of binary result
	/// REAIT storing directory
	private String reaiDir;
	private String exportBinPath;
	private String configPath = System.getProperty("user.home") + File.separator + ".reaiconf.toml";
	
	/**
	 * Singleton constructor
	 */
	private REAITHelper() {
		this.reaiDir = System.getProperty("user.home") + File.separator + ".reait";
		this.setExportBinPath(this.reaiDir + File.separator + "exported.bin");
		if (new File(configPath).exists()) {
			System.out.println("here");
			client = new Client(configPath);
		}
	}
	
	/**
	 * 
	 * @return instance of the Helper object
	 */
	public static REAITHelper getInstance() {
		if (instance == null) {
			instance = new REAITHelper();
		}
		
		return instance;
	}

	public Client getClient() {
		return client;
	}

	public void setClient(Client client) {
		this.client = client;
	}

	public FlatProgramAPI getFlatAPI() {
		return flatAPI;
	}

	public void setFlatAPI(FlatProgramAPI flatAPI) {
		this.flatAPI = flatAPI;
	}

	public String getReaiDir() {
		return reaiDir;
	}

	public void setReaiDir(String reaiDir) {
		this.reaiDir = reaiDir;
	}

	public String getExportBinPath() {
		return exportBinPath;
	}

	public void setExportBinPath(String exportBinPath) {
		this.exportBinPath = exportBinPath;
	}
}
