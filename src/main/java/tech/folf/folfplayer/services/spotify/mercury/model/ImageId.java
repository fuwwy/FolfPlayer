package tech.folf.folfplayer.services.spotify.mercury.model;

import com.spotify.connectstate.Player;
import com.spotify.metadata.Metadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tech.folf.folfplayer.Utils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Gianlu
 */
public final class ImageId implements SpotifyId {
    public static final String[] IMAGE_SIZES_URLS = new String[]{"image_xlarge_url", "image_large_url", "image_url", "image_small_url"};
    private static final Pattern PATTERN = Pattern.compile("spotify:image:(.{40})");
    private final String hexId;

    private ImageId(@NotNull String hex) {
        this.hexId = hex.toLowerCase();
    }

    @NotNull
    public static ImageId fromUri(@NotNull String uri) {
        Matcher matcher = PATTERN.matcher(uri);
        if (matcher.find()) return new ImageId(matcher.group(1));
        else throw new IllegalArgumentException("Not a Spotify image ID: " + uri);
    }

    @NotNull
    public static ImageId fromHex(@NotNull String hex) {
        return new ImageId(hex);
    }

    @Nullable
    public static ImageId biggestImage(@NotNull Metadata.ImageGroup group) {
        Metadata.Image biggest = null;
        for (Metadata.Image image : group.getImageList()) {
            if (biggest == null || biggest.getSize().getNumber() < image.getSize().getNumber())
                biggest = image;
        }

        return biggest == null ? null : fromHex(Utils.bytesToHex(biggest.getFileId()));
    }

    public static void putAsMetadata(@NotNull Player.ProvidedTrack.Builder builder, @NotNull Metadata.ImageGroup group) {
        for (Metadata.Image image : group.getImageList()) {
            String key;
            switch (image.getSize()) {
                case DEFAULT:
                    key = "image_url";
                    break;
                case SMALL:
                    key = "image_small_url";
                    break;
                case LARGE:
                    key = "image_large_url";
                    break;
                case XLARGE:
                    key = "image_xlarge_url";
                    break;
                default:
                    continue;
            }

            builder.putMetadata(key, fromHex(Utils.bytesToHex(image.getFileId())).toSpotifyUri());
        }
    }

    @Override
    public @NotNull String toSpotifyUri() {
        return "spotify:image:" + hexId;
    }

    @NotNull
    public String hexId() {
        return hexId;
    }
}
