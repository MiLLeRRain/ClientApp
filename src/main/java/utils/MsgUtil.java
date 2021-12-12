package utils;

import org.springframework.boot.configurationprocessor.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

// It is a place to build JsonObject type msg
// read from incoming instructor including header
// assemble it using header part and msg part
public class MsgUtil {

    Map<String, Object> msg = new HashMap<>();

    public static JSONObject pack(String header, Object data) {

        return null;
    }

    public static Map<String, String> unpack() {
        return null;
    }


}
