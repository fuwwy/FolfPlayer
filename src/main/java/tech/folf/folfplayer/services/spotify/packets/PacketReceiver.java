package tech.folf.folfplayer.services.spotify.packets;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xml.sax.SAXException;
import tech.folf.folfplayer.Utils;
import tech.folf.folfplayer.services.spotify.SpotifyService;
import tech.folf.folfplayer.services.spotify.crypto.Packet;
import tech.folf.folfplayer.services.spotify.utils.TimeProvider;

import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class PacketReceiver implements Runnable {
    private static final Logger LOGGER = LogManager.getLogger(PacketReceiver.class);
    private final Thread thread;
    private volatile boolean running = true;
    private final SpotifyService spotifyService;

    public PacketReceiver(SpotifyService spotifyService) {
        this.spotifyService = spotifyService;
        thread = new Thread(this, "session-packet-receiver");
        thread.start();
    }

    void stop() {
        running = false;
        thread.interrupt();
    }

    @Override
    public void run() {
        LOGGER.trace("Session.Receiver started");

        while (running) {
            Packet packet;
            Packet.Type cmd;
            try {
                packet = spotifyService.getCipherPair().receiveEncoded(spotifyService.getConn().in);
                cmd = Packet.Type.parse(packet.cmd);
                if (cmd == null) {
                    LOGGER.info("Skipping unknown command {cmd: 0x{}, payload: {}}", Integer.toHexString(packet.cmd), Utils.bytesToHex(packet.payload));
                    continue;
                }
            } catch (IOException | GeneralSecurityException ex) {
                if (running) {
                    LOGGER.fatal("Failed reading packet!", ex);
                    //reconnect();
                }

                break;
            }

            if (!running) break;

            switch (cmd) {
                case Ping:
                    ScheduledFuture<?> scheduledReconnect = spotifyService.getScheduledReconnect();
                    if (scheduledReconnect != null) scheduledReconnect.cancel(true);
                    scheduledReconnect = spotifyService.getScheduler().schedule(() -> {
                        LOGGER.warn("Socket timed out. Reconnecting...");
                        //reconnect();
                    }, 2 * 60 + 5, TimeUnit.SECONDS);

                    TimeProvider.updateWithPing(packet.payload);

                    try {
                        spotifyService.send(Packet.Type.Pong, packet.payload);
                    } catch (IOException ex) {
                        LOGGER.fatal("Failed sending Pong!", ex);
                    }
                    break;
                case PongAck:
                    // Silent
                    break;
                case CountryCode:
                    LOGGER.info("Received CountryCode: " + new String(packet.payload));
                    break;
                case LicenseVersion:
                    ByteBuffer licenseVersion = ByteBuffer.wrap(packet.payload);
                    short id = licenseVersion.getShort();
                    if (id != 0) {
                        byte[] buffer = new byte[licenseVersion.get()];
                        licenseVersion.get(buffer);
                        LOGGER.info("Received LicenseVersion: {}, {}", id, new String(buffer));
                    } else {
                        LOGGER.info("Received LicenseVersion: {}", id);
                    }
                    break;
                case Unknown_0x10:
                    LOGGER.debug("Received 0x10: " + Utils.bytesToHex(packet.payload));
                    break;
                case MercurySub:
                case MercuryUnsub:
                case MercuryEvent:
                case MercuryReq:
                    spotifyService.mercury().dispatch(packet);
                    break;
                /*    case AesKey:
                    case AesKeyError:
                        audioKey().dispatch(packet);
                        break;
                    case ChannelError:
                    case StreamChunkRes:
                        channel().dispatch(packet);
                        break;*/
                case ProductInfo:
                    try {
                        spotifyService.parseProductInfo(new ByteArrayInputStream(packet.payload));
                    } catch (IOException | ParserConfigurationException | SAXException ex) {
                        LOGGER.warn("Failed parsing prodcut info!", ex);
                    }
                    break;
                default:
                    LOGGER.info("Skipping " + cmd.name());
                    break;
            }
        }

        LOGGER.trace("Session.Receiver stopped");
    }
}