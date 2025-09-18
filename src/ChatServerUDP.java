import java.net.*;
import java.security.PublicKey;
import java.util.*;
import java.util.Base64;

public class ChatServerUDP {
    private static final int PORT = 50001;
    private static final int BUFFER_SIZE = 4096;

    private static Map<String, InetSocketAddress> clients = new HashMap<>();
    private static Map<String, PublicKey> clientPublicKeys = new HashMap<>();

    public static void main(String[] args) throws Exception {
        DatagramSocket socket = new DatagramSocket(PORT);
        byte[] buffer = new byte[BUFFER_SIZE];
        System.out.println("Servidor UDP pronto na porta " + PORT);

        while (true) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);

            String received = new String(packet.getData(), 0, packet.getLength());
            InetAddress address = packet.getAddress();
            int port = packet.getPort();

            if (received.startsWith("REGISTRO:")) {
                String[] parts = received.split(":", 3);
                String username = parts[1];
                PublicKey pk = RSAUtils.stringToPublicKey(parts[2]);

                clients.put(username, new InetSocketAddress(address, port));
                clientPublicKeys.put(username, pk);

                broadcast(socket, username + " entrou no chat.");
                continue;
            }

            if (received.startsWith("SAIR:")) {
                String username = received.substring(5).trim();
                clients.remove(username);
                clientPublicKeys.remove(username);

                broadcast(socket, username + " saiu do chat.");
                continue;
            }

            if (received.startsWith("LISTAR_USUARIOS:")) {
                StringBuilder userList = new StringBuilder("Usuários registrados:\n");
                for (String user : clients.keySet()) {
                    userList.append("- ").append(user).append("\n");
                }
                send(socket, userList.toString(), address, port);
                continue;
            }

            if (received.startsWith("BROADCAST:")) {
                String[] parts = received.split(":", 3);
                String from = parts[1];
                String msg = "[Todos] " + from + ": " + parts[2];
                broadcast(socket, msg);
                continue;
            }

            if (received.startsWith("PRIVADO:")) {
                String[] parts = received.split(":", 5);
                String from = parts[1];
                String to = parts[2];
                boolean secure = parts[3].equalsIgnoreCase("SECURE");

                if (!clients.containsKey(to)) {
                    System.out.println("Usuário " + to + " não encontrado.");
                    continue;
                }

                if (secure) {
                    String signatureB64 = parts[4].split(" ", 2)[0];
                    String msg = parts[4].substring(signatureB64.length()).trim();

                    try {
                        PublicKey destKey = clientPublicKeys.get(to);
                        PublicKey senderKey = clientPublicKeys.get(from);

                        byte[] encrypted = RSAUtils.encrypt(msg, destKey);

                        String packetMsg = "ENCRYPTED:" + from + ":" +
                                Base64.getEncoder().encodeToString(encrypted) + ":" +
                                signatureB64 + ":" +
                                RSAUtils.keyToString(senderKey);

                        send(socket, packetMsg, clients.get(to).getAddress(), clients.get(to).getPort());
                        System.out.println("[Privado-SECURE] " + from + " → " + to + ": " + msg);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    String msg = parts[3];
                    String finalMsg = "[Privado] " + from + ": " + msg;
                    InetSocketAddress dest = clients.get(to);
                    send(socket, finalMsg, dest.getAddress(), dest.getPort());
                    System.out.println(finalMsg);
                }
            }
        }
    }

    private static void broadcast(DatagramSocket socket, String message) throws Exception {
        for (InetSocketAddress dest : clients.values()) {
            send(socket, message, dest.getAddress(), dest.getPort());
        }
        System.out.println(message);
    }

    private static void send(DatagramSocket socket, String msg, InetAddress addr, int port) throws Exception {
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr, port);
        socket.send(packet);
    }
}
