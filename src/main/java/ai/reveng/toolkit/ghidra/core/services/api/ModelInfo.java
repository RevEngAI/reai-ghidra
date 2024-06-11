package ai.reveng.toolkit.ghidra.core.services.api;

import org.json.JSONObject;

import java.util.regex.Pattern;

/**
 * Object that models a RevEng.ai model
 * 
 * TODO Create either an enum or method that checks for valid names and version
 */
public class ModelInfo {
	private String name;
	private int majVersion;
	private int minVersion;

	/**
	 * Create a new model using a separate name and version
	 * 
	 * @param name       model name, e.g. "binnet"
	 * @param majVersion major version of model
	 * @param minVersion minor version of model
	 * 
	 */
	public ModelInfo(String name, int majVersion, int minVersion) {
		this.name = name;
		this.majVersion = majVersion;
		this.minVersion = minVersion;
	}

	/**
	 * Create a new model from a string
	 * 
	 * @param modelString model identifier in the form {name}-{version}
	 */
	public ModelInfo(String modelString) {
		// TODO check string is in valid format
		this.name = modelString.split("-")[0];
		try {
			this.majVersion = Integer.parseInt(modelString.split("-")[1].split(Pattern.quote("."))[0]);
		} catch (IndexOutOfBoundsException e) {
			System.err.println("No major version provided");
			this.majVersion = 0;
		}
		try {
			this.minVersion = Integer.parseInt(modelString.split("-")[1].split(Pattern.quote("."))[1]);
		} catch (IndexOutOfBoundsException e) {
			System.err.println("No minor version provided");
			this.minVersion = 0;
		}

	}

	public static ModelInfo fromJSONObject(JSONObject o) {
		return new ModelInfo(o.getString("model_name"));
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public int getMajVersion() {
		return this.majVersion;
	}

	public void setMajVersion(int majVersion) {
		this.majVersion = majVersion;
	}

	public int getMinVersion() {
		return this.minVersion;
	}

	public void setMinVersion(int minVersion) {
		this.minVersion = minVersion;
	}

	public String toString() {
		return this.name + "-" + this.majVersion + "." + this.minVersion;
	}
}