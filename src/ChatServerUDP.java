import java.net.*;
import java.security.PublicKey;
import java.util.*;

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

                // Notificação deve ir para todos, inclusive o próprio
                broadcast(socket, username + " entrou no chat.", null);
                continue;
            }

            if (received.startsWith("SAIR:")) {
                String username = received.substring(5).trim();
                clients.remove(username);
                clientPublicKeys.remove(username);

                // Notificação deve ir para todos
                broadcast(socket, username + " saiu do chat.", null);
                continue;
            }

            if (received.startsWith("LISTAR_USUARIOS:")) {
                StringBuilder userList = new StringBuilder("Usuarios registrados:\n");
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
                // broadcast normal → não volta para o remetente
                broadcast(socket, msg, from);
                continue;
            }

            if (received.startsWith("PRIVADO:")) {
                String[] parts = received.split(":", 6); // agora 6 partes!
                String from = parts[1];
                String to = parts[2];
                boolean secure = parts[3].equalsIgnoreCase("SECURE");

                if (!clients.containsKey(to)) {
                    System.out.println("Usuario " + to + " nao encontrado.");
                    continue;
                }

                if (secure) {
                    try {
                        PublicKey destKey = clientPublicKeys.get(to);
                        PublicKey senderKey = clientPublicKeys.get(from);

                        byte[] encrypted = RSAUtils.encrypt(msg, destKey); // criptografa msg clara

                        String packetMsg = "ENCRYPTED:" + from + ":" +
                                Base64.getEncoder().encodeToString(encrypted) + ":" +
                                Base64.getEncoder().encodeToString(signatureB64.getBytes()) + ":" +
                                RSAUtils.keyToString(senderKey);

                        // envia somente o pacote criptografado, sem a msg clara
                        InetSocketAddress dest = clients.get(to);
                        send(socket, packetMsg, dest.getAddress(), dest.getPort());

                        System.out.println("[Privado-SECURE] " + from + " para " + to + ": " + msg);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                else {
                    String msg = parts[3]; // aqui a msg está direto
                    String finalMsg = "[Privado] " + from + " para " + to + ": " + msg;
                    InetSocketAddress dest = clients.get(to);
                    send(socket, finalMsg, dest.getAddress(), dest.getPort());
                    System.out.println(finalMsg);
                }
            }
        }
    }

    /**
     * Se "from" == null → notificação (vai para todos, inclusive quem causou).
     * Caso contrário → mensagem normal (não volta para o remetente).
     */
    private static void broadcast(DatagramSocket socket, String message, String from) throws Exception {
        for (Map.Entry<String, InetSocketAddress> entry : clients.entrySet()) {
            if (from != null && entry.getKey().equals(from)) continue; // não envia para quem enviou
            send(socket, message, entry.getValue().getAddress(), entry.getValue().getPort());
        }
        System.out.println(message); // log do servidor
    }

    private static void send(DatagramSocket socket, String msg, InetAddress addr, int port) throws Exception {
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr, port);
        socket.send(packet);
    }
}
