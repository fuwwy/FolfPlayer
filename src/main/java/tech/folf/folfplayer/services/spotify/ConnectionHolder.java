package tech.folf.folfplayer.services.spotify;

import com.sun.istack.internal.NotNull;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class ConnectionHolder {
    public final Socket socket;
    public final DataInputStream in;
    public final DataOutputStream out;

    private ConnectionHolder(@NotNull Socket socket) throws IOException {
        this.socket = socket;
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
    }

    static ConnectionHolder create(@NotNull String addr) throws IOException {
        int colon = addr.indexOf(':');
        String apAddr = addr.substring(0, colon);
        int apPort = Integer.parseInt(addr.substring(colon + 1));
        return new ConnectionHolder(new Socket(apAddr, apPort));
    }
}