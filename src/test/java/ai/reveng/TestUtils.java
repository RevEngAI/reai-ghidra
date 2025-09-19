package ai.reveng;

import ai.reveng.toolkit.ghidra.core.services.api.types.ApiInfo;

import java.io.FileNotFoundException;

public class TestUtils {

    public static ApiInfo getApiInfoForTesting() {

        try {
            return ApiInfo.fromConfig();
        } catch (FileNotFoundException e) {
            org.junit.Assume.assumeTrue(false);
            throw  new RuntimeException(e);
        }
    }
}
