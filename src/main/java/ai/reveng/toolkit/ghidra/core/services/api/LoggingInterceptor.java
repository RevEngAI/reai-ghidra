package ai.reveng.toolkit.ghidra.core.services.api;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.function.Consumer;
import java.nio.charset.StandardCharsets;

import ghidra.util.Msg;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;
import okhttp3.MediaType;
import okhttp3.RequestBody;
import okio.Buffer;

public class LoggingInterceptor implements Interceptor {
    private final boolean withBody;
    private final Consumer<String> logFunction;
    private final int maxBodyLength;

    // Constructor takes any lambda that accepts a String
    public LoggingInterceptor(Consumer<String> logFunction, boolean withBody) {
        this.logFunction = logFunction;
        this.withBody = withBody;
        this.maxBodyLength = 2048; // Limit body length to 2048 characters
    }

    @Override
    public @NotNull Response intercept(Chain chain) throws IOException {
        Request request = chain.request();

        long startNs = System.nanoTime();
        Response response = chain.proceed(request);
        long tookMs = (System.nanoTime() - startNs) / 1_000_000L;

        String logMessage = String.format(
                "HTTP %s %s -> %d (%d ms)",
                request.method(),
                request.url(),
                response.code(),
                tookMs
        );

        if (logFunction != null) {
            logFunction.accept(logMessage);
        }

        if (withBody && request.body() != null) {
            String bodyText = readRequestBody(request);
            if (bodyText != null && !bodyText.isEmpty() && logFunction != null) {
                logFunction.accept("Request Body: " + bodyText);
            }
        }

        if (withBody && response.body() != null) {
            String responseBody = response.peekBody(maxBodyLength).string();
            if (logFunction != null) {
                logFunction.accept("Response Body: " + responseBody);
            }
        }

        return response;
    }

    private String readRequestBody(Request request) {
        try {
            RequestBody body = request.body();
            if (body == null) return null;

            MediaType contentType = body.contentType();
            if (contentType != null && !isTextMediaType(contentType)) {
                return "[non-text body omitted: " + contentType + "]";
            }

            Buffer buffer = new Buffer();
            body.writeTo(buffer);

            Charset charset = (contentType != null && contentType.charset() != null)
                    ? contentType.charset(StandardCharsets.UTF_8)
                    : StandardCharsets.UTF_8;

            assert charset != null;
            String fullBody = buffer.readString(charset);

            if (fullBody.length() > maxBodyLength) {
                return fullBody.substring(0, maxBodyLength) + "…[truncated]";
            }

            return fullBody;
        } catch (Exception e) {
            return "[error reading body: " + e.getMessage() + "]";
        }
    }

    private boolean isTextMediaType(MediaType type) {
        String subtype = type.subtype();
        return subtype.contains("json") || subtype.contains("xml") || subtype.contains("plain") || subtype.contains("html") || subtype.contains("form");
    }

    // Static factory method for creating a Ghidra-specific logger
    public static LoggingInterceptor ghidraLogger(boolean withBody) {
        return new LoggingInterceptor(
            message -> Msg.info(LoggingInterceptor.class, message),
            withBody
        );
    }
}