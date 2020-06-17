package tech.folf.folfplayer.services.spotify.mercury;

import org.jetbrains.annotations.NotNull;

/**
 * @author Gianlu
 */
public interface SubListener {
    void event(@NotNull MercuryClient.Response resp);
}
