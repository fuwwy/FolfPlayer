package tech.folf.folfplayer;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import tech.folf.folfplayer.services.spotify.SpotifyService;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class FolfPlayer {

    public static void main(String[] args) throws SpotifyService.SpotifyAuthenticationException, GeneralSecurityException, IOException {
        Configurator.setRootLevel(Level.ALL);
    }
}
