import java.net.*;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ChatServerUDP {
    private static final int PORT = 50001;
    private static final int BUFFER_SIZE = 8192;

    // username -> endereço
    private static Map<String, InetSocketAddress> clients = new ConcurrentHashMap<>();
    // username -> chave pública
    private static Map<String, PublicKey> clientPublicKeys = new ConcurrentHashMap<>();

    public static void main(String[] args) throws Exception {
        DatagramSocket socket = new DatagramSocket(PORT);
        System.out.println("Servidor UDP pronto na porta " + PORT);

        byte[] buffer = new byte[BUFFER_SIZE];

        while (true) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);

            String msg = new String(packet.getData(), 0, packet.getLength());
            InetAddress addr = packet.getAddress();
            int port = packet.getPort();

            if (msg.startsWith("REGISTRO:")) {
                String[] parts = msg.split(":", 3);
                String username = parts[1];
                PublicKey pk = RSAUtils.stringToPublicKey(parts[2]);

                clients.put(username, new InetSocketAddress(addr, port));
                clientPublicKeys.put(username, pk);

                broadcast(socket, username + " entrou no chat.", null);
                continue;
            }

            if (msg.startsWith("SAIR:")) {
                String username = msg.substring(5).trim();
                clients.remove(username);
                clientPublicKeys.remove(username);

                broadcast(socket, username + " saiu do chat.", null);
                continue;
            }

            if (msg.startsWith("LISTAR_USUARIOS:")) {
                StringBuilder sb = new StringBuilder("Usuarios registrados:\n");
                for (String u : clients.keySet()) sb.append("- ").append(u).append("\n");
                send(socket, sb.toString(), addr, port);
                continue;
            }

            if (msg.startsWith("REQKEY:")) {
                String target = msg.substring(7).trim();
                PublicKey targetKey = clientPublicKeys.get(target);
                if (targetKey != null) {
                    send(socket, "PUBKEYRESP:" + target + ":" + RSAUtils.keyToString(targetKey), addr, port);
                } else {
                    send(socket, "ERRO:Nao foi possivel obter a chave de " + target, addr, port);
                }
                continue;
            }

            if (msg.startsWith("BROADCAST:")) {
                String[] parts = msg.split(":", 3);
                String from = parts[1];
                String text = "[Todos] " + from + ": " + parts[2];
                broadcast(socket, text, from);
                continue;
            }

            if (msg.startsWith("PRIVADO:")) {
                String[] parts = msg.split(":", 6);
                String from = parts[1];
                String to = parts[2];
                boolean secure = parts[3].equalsIgnoreCase("SECURE");

                InetSocketAddress destAddr = clients.get(to);
                if (destAddr == null) {
                    System.out.println("Usuario " + to + " nao encontrado.");
                    continue;
                }

                if (secure) {
                    // encaminha pacote criptografado direto
                    send(socket, msg, destAddr.getAddress(), destAddr.getPort());
                    // System.out.println("[Privado-SECURE] " + from + " para " + to);
                } else {
                    String text = parts[3]; // mensagem clara
                    send(socket, "[Privado] " + from + " para " + to + ": " + text,
                         destAddr.getAddress(), destAddr.getPort());
                    System.out.println("[Privado] " + from + " para " + to + ": " + text);
                }
            }
        }
    }

    private static void broadcast(DatagramSocket socket, String msg, String from) throws Exception {
        for (Map.Entry<String, InetSocketAddress> entry : clients.entrySet()) {
            if (from != null && entry.getKey().equals(from)) continue;
            send(socket, msg, entry.getValue().getAddress(), entry.getValue().getPort());
        }
        System.out.println(msg);
    }

    private static void send(DatagramSocket socket, String msg, InetAddress addr, int port) throws Exception {
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr, port);
        socket.send(packet);
    }
}
