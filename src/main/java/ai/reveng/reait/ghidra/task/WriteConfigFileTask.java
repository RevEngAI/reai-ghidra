package ai.reveng.reait.ghidra.task;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

import com.moandjiezana.toml.TomlWriter;

import ai.reveng.reait.REAITConfig;
import ai.reveng.reait.ghidra.REAITHelper;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class WriteConfigFileTask extends Task {
	private TaskCallback<String> callback;

	public WriteConfigFileTask(TaskCallback<String> callback) {
		super("Write Config File to disk", true, false, false);
		this.callback = callback;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		String path = System.getProperty("user.home") + File.separator + ".reaiconf.toml";

		HashMap<String, String> configMap = new HashMap<String, String>();
		REAITConfig conf = REAITHelper.getInstance().getClient().getConfig();
		configMap.put("apikey", conf.getApiKey());
		configMap.put("host", conf.getHost());
		configMap.put("model", conf.getModel().toString());

		TomlWriter tomlWriter = new TomlWriter();
		try {
			tomlWriter.write(configMap, new File(path));
			this.callback.onTaskCompleted(path);
		} catch (IOException e) {
			this.callback.onTaskError(e);
		}
	}

}
