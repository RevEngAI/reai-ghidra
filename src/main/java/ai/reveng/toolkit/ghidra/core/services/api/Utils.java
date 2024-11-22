package ai.reveng.toolkit.ghidra.core.services.api;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

class Utils {

    public static <T> List<T> mapJSONArray(JSONArray jsonArray, Function<JSONObject, T> mapper) {
        var result = new ArrayList<T>();
        jsonArray.forEach(o -> result.add(mapper.apply((JSONObject) o)));
        return result;
    }
}
