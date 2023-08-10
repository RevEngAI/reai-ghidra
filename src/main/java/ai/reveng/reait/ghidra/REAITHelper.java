package ai.reveng.reait.ghidra;

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
	
	/**
	 * Singleton constructor
	 */
	private REAITHelper() {
		return;
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
}
