package tech.folf.folfplayer.services.spotify.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.Closeable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

public class AsyncProcessor<REQ, RES> implements Closeable {
    private static final Logger LOGGER = LogManager.getLogger(AsyncProcessor.class);
    private final String name;
    private final Function<REQ, RES> processor;
    private final ExecutorService executor;

    /**
     * @param name      name of async processor - used for thread name and logging
     * @param processor actual processing implementation ran on background thread
     */
    public AsyncProcessor(@org.jetbrains.annotations.NotNull String name, @org.jetbrains.annotations.NotNull Function<REQ, RES> processor) {
        executor = Executors.newSingleThreadExecutor(new NameThreadFactory(r -> name));
        this.name = name;
        this.processor = processor;
        LOGGER.trace("AsyncProcessor{{}} has started", name);
    }

    public Future<RES> submit(@org.jetbrains.annotations.NotNull REQ task) {
        return executor.submit(() -> processor.apply(task));
    }

    public boolean awaitTermination(long timeout, @org.jetbrains.annotations.NotNull TimeUnit unit) throws InterruptedException {
        if (!executor.isShutdown())
            throw new IllegalStateException(String.format("AsyncProcessor{%s} hasn't been shut down yet", name));

        if (executor.awaitTermination(timeout, unit)) {
            LOGGER.trace("AsyncProcessor{{}} is shut down", name);
            return true;
        } else {
            return false;
        }
    }

    @Override
    public void close() {
        LOGGER.trace("AsyncProcessor{{}} is shutting down", name);
        executor.shutdown();
    }
}

