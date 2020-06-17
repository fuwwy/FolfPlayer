package tech.folf.folfplayer.services.spotify.utils;

import java.io.Closeable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class AsyncWorker<T> implements Closeable {
    private final AsyncProcessor<T, Void> underlyingProcessor;

    public AsyncWorker(@org.jetbrains.annotations.NotNull String name, @org.jetbrains.annotations.NotNull Consumer<T> consumer) {
        this.underlyingProcessor = new AsyncProcessor<>(name, t -> {
            consumer.accept(t);
            return null;
        });
    }

    @org.jetbrains.annotations.NotNull
    public Future<Void> submit(@org.jetbrains.annotations.NotNull T task) {
        return underlyingProcessor.submit(task);
    }

    public boolean awaitTermination(long timeout, @org.jetbrains.annotations.NotNull TimeUnit unit) throws InterruptedException {
        return underlyingProcessor.awaitTermination(timeout, unit);
    }

    @Override
    public void close() {
        underlyingProcessor.close();
    }
}
