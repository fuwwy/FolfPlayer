package tech.folf.folfplayer.services.spotify.utils;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.istack.internal.NotNull;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

public final class ApResolver {
    private static final String BASE_URL = "http://apresolve.spotify.com/";
    private static final Map<String, List<String>> pool = new HashMap<>(3);
    private static final Logger LOGGER = LogManager.getLogger(ApResolver.class);
    private static volatile boolean poolReady = false;

    public static void fillPool() throws IOException {
        if (!poolReady) request("accesspoint", "dealer", "spclient");
    }

    @NotNull
    private static List<String> getUrls(@NotNull JsonObject body, @NotNull String type) {
        JsonArray aps = body.getAsJsonArray(type);
        List<String> list = new ArrayList<>(aps.size());
        for (JsonElement ap : aps) list.add(ap.getAsString());
        return list;
    }

    @NotNull
    private static Map<String, List<String>> request(@NotNull String... types) throws IOException {
        if (types.length == 0) throw new IllegalArgumentException();

        StringBuilder url = new StringBuilder(BASE_URL + "?");
        for (int i = 0; i < types.length; i++) {
            if (i != 0) url.append("&");
            url.append("type=").append(types[i]);
        }

        HttpURLConnection conn = (HttpURLConnection) new URL(url.toString()).openConnection();
        conn.connect();

        try (Reader reader = new InputStreamReader(conn.getInputStream())) {
            JsonObject obj = JsonParser.parseReader(reader).getAsJsonObject();
            HashMap<String, List<String>> map = new HashMap<>();
            for (String type : types)
                map.put(type, getUrls(obj, type));

            synchronized (pool) {
                pool.putAll(map);
                poolReady = true;
                pool.notifyAll();
            }

            LOGGER.info("Loaded aps into pool: " + pool.toString());

            return map;
        } finally {
            conn.disconnect();
        }
    }

    private static void waitForPool() {
        if (!poolReady) {
            synchronized (pool) {
                try {
                    pool.wait();
                } catch (InterruptedException ex) {
                    throw new IllegalStateException(ex);
                }
            }
        }
    }

    @NotNull
    private static String getRandomOf(@NotNull String type) {
        waitForPool();

        List<String> urls = pool.get(type);
        if (urls == null || urls.isEmpty()) throw new IllegalStateException();
        return urls.get(ThreadLocalRandom.current().nextInt(urls.size()));
    }

    @NotNull
    public static String getRandomDealer() {
        return getRandomOf("dealer");
    }

    @NotNull
    public static String getRandomSpclient() {
        return getRandomOf("spclient");
    }

    @NotNull
    public static String getRandomAccesspoint() {
        return getRandomOf("accesspoint");
    }
}
