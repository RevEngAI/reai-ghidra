package ai.reveng.toolkit.ghidra.core.services.logging;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import ghidra.util.Msg;

/**
 * Very simple logging service to enable use to export error logs
 */
public class ReaiLoggingServiceImpl implements ReaiLoggingService {
	private static final Logger logger = Logger.getLogger("REAIPlugin");
	private static FileHandler fileHandler;
	private static String uHome = System.getProperty("user.home");
	private static Path logDir = Paths.get(uHome, ".reai/logs");
	private static Path logFilePath = Paths.get(logDir.toString(), "ReaiLogFile.txt");
	
	static {
		createLogsDirectory();
		
		try {
			fileHandler = new FileHandler(logFilePath.toString(), true);
			logger.addHandler(fileHandler);
			
			SimpleFormatter formatter = new SimpleFormatter();
			fileHandler.setFormatter(formatter);
		} catch (SecurityException | IOException e) {
			Msg.error(ReaiLoggingServiceImpl.class, "Cannot create logfile: " + e.getMessage());
		}
	}
	
	private static void createLogsDirectory() {
		try {
			Files.createDirectories(logDir);
		} catch (IOException e) {
			Msg.error(ReaiLoggingServiceImpl.class, "Unable to create logs directory: " + e.getMessage());
		}
	}

	@Override
	public void info(String message) {
		logger.info(message);	
	}

	@Override
	public void warn(String message) {
		logger.warning(message);
	}

	@Override
	public void error(String message) {
		logger.severe(message);
	}

	@Override
	public void export(String targetDirectoryPath, String exportedFileName) {
		Path targetPath = Paths.get(targetDirectoryPath, exportedFileName);
		
		try {
			Files.createDirectories(targetPath);
            Files.copy(logFilePath, targetPath, StandardCopyOption.REPLACE_EXISTING);
            Msg.info(ReaiLoggingServiceImpl.class, "Log file successfully exported to: " + targetPath);
		} catch (IOException e) {
			Msg.error(ReaiLoggingServiceImpl.class, "Unable to export logfile: " + e.getMessage());
		}
	}
}
