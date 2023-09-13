package ai.reveng.toolkit.ghidra.core.services.api;

import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;

public class Utils {

	public static String formatBinaryEmbeding(List<List<Double>> listList) {
		StringBuilder stringBuilder = new StringBuilder("[");

		for (int i = 0; i < listList.size(); i++) {
			List<Double> innerList = listList.get(i);
			stringBuilder.append("[");

			for (int j = 0; j < innerList.size(); j++) {
				stringBuilder.append(innerList.get(j));

				if (j < innerList.size() - 1) {
					stringBuilder.append(", ");
				}
			}

			stringBuilder.append("]");

			if (i < listList.size() - 1) {
				stringBuilder.append(", ");
			}
		}

		stringBuilder.append("]");
		return stringBuilder.toString();
	}

	public static String[] jsonArrayToStringArray(JSONArray jsonArray) {
		int length = jsonArray.length();
		String[] stringArray = new String[length];
		for (int i = 0; i < length; i++) {
			try {
				stringArray[i] = jsonArray.getString(i);
			} catch (JSONException e) {
				e.printStackTrace();
			}
		}
		return stringArray;
	}
}
