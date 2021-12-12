package utils;

import java.net.InetAddress;
import java.net.Socket;
import java.util.Date;

public class UserNode {
    private String username;
    private String password;
    private Socket socket;
    private String AESKey;
    private String connectTime;

    public UserNode(String username, Socket socket, String AESKey) {
        this.username = username;
        this.connectTime = new Date().toString();
        this.socket = socket;
        this.AESKey = AESKey;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAESKey() {
        return AESKey;
    }

    public void setAESKey(String AESKey) {
        this.AESKey = AESKey;
    }

    public String getConnectTime() {
        return connectTime;
    }

    public void setConnectTime(String connectTime) {
        this.connectTime = connectTime;
    }

    public Socket getSocket() {
        return socket;
    }

    public void setSocket(Socket socket) {
        this.socket = socket;
    }

    @Override
    public int hashCode() {
        return username.hashCode() + socket.hashCode();
    }

    @Override
    public boolean equals(Object that) {
        return (that instanceof UserNode
                && username == ((UserNode) that).username);
    }
}
