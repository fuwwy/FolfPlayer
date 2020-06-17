package tech.folf.folfplayer.services.spotify.packets;

import org.jetbrains.annotations.NotNull;
import tech.folf.folfplayer.Utils;
import tech.folf.folfplayer.services.spotify.SpotifyService;
import tech.folf.folfplayer.services.spotify.crypto.Packet;
import tech.folf.folfplayer.services.spotify.utils.AsyncWorker;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.ExecutorService;

/**
 * @author Gianlu
 */
public abstract class PacketsManager implements Closeable {
    protected final SpotifyService session;
    private final ExecutorService executorService;
    private final AsyncWorker<Packet> asyncWorker;

    public PacketsManager(@NotNull SpotifyService session, @NotNull String name) {
        this.session = session;
        this.executorService = session.executor();
        this.asyncWorker = new AsyncWorker<>("pm-" + name, packet -> executorService.execute(() -> {
            try {
                handle(packet);
            } catch (IOException ex) {
                exception(ex);
            }
        }));
    }

    public final void dispatch(@NotNull Packet packet) {
        appendToQueue(packet);
    }

    @Override
    public void close() {
        asyncWorker.close();
    }

    /**
     * This method can be overridden to process packet synchronously. This MUST not block for a long period of time.
     */
    protected void appendToQueue(@NotNull Packet packet) {
        asyncWorker.submit(packet);
    }

    protected abstract void handle(@NotNull Packet packet) throws IOException;

    protected abstract void exception(@NotNull Exception ex);
}
