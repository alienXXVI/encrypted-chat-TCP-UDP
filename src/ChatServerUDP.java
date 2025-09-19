import java.net.*;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Servidor de chat UDP que gerencia a comunicação baseada em pacotes.
 * Armazena endereços e chaves públicas de clientes para roteamento
 * de mensagens e lida com mensagens de texto e criptografadas.
 *
 * @author [Seu Nome]
 * @version 1.0
 */
public class ChatServerUDP {
    private static final int PORT = 50001;
    private static final int BUFFER_SIZE = 8192;

    // username -> endereço
    private static Map<String, InetSocketAddress> clients = new ConcurrentHashMap<>();
    // username -> chave pública
    private static Map<String, PublicKey> clientPublicKeys = new ConcurrentHashMap<>();

    /**
     * Ponto de entrada principal do servidor UDP. Inicia o DatagramSocket
     * e entra em um loop infinito para receber e processar pacotes.
     *
     * @param args Argumentos da linha de comando (não utilizados).
     * @throws Exception Se ocorrer um erro durante a inicialização.
     */
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

                // Envia todas as chaves já registradas para o novo usuário
                StringBuilder sb = new StringBuilder("LISTA_KEYS:\n");
                for (Map.Entry<String, PublicKey> entry : clientPublicKeys.entrySet()) {
                    sb.append(entry.getKey()).append(":")
                    .append(RSAUtils.keyToString(entry.getValue())).append("\n");
                }
                send(socket, sb.toString(), addr, port);

                // Notifica todos os outros sobre a chave do novo usuário
                String newKeyMsg = "NEWKEY:" + username + ":" + RSAUtils.keyToString(pk);
                broadcast(socket, newKeyMsg, username);

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
                    send(socket, msg, destAddr.getAddress(), destAddr.getPort());
                    // System.out.println("[Privado-SECURE] " + from + " para " + to);
                } else {
                    String text = parts[3];
                    send(socket, "[Privado] " + from + ": " + text,
                         destAddr.getAddress(), destAddr.getPort());
                    System.out.println("[Privado] " + from + " para " + to + ": " + text);
                }
            }
        }
    }

    /**
     * Envia uma mensagem de broadcast para todos os clientes registrados.
     *
     * @param socket O DatagramSocket do servidor.
     * @param msg A mensagem a ser enviada.
     * @param from O nome do usuário remetente (para evitar enviar para ele mesmo).
     * @throws Exception Se ocorrer um erro de I/O.
     */
    private static void broadcast(DatagramSocket socket, String msg, String from) throws Exception {
        for (Map.Entry<String, InetSocketAddress> entry : clients.entrySet()) {
            if (from != null && entry.getKey().equals(from)) continue;
            send(socket, msg, entry.getValue().getAddress(), entry.getValue().getPort());
        }
        System.out.println(msg);
    }

    /**
     * Envia um pacote de datagrama para um endereço e porta específicos.
     *
     * @param socket O DatagramSocket do servidor.
     * @param msg A mensagem a ser enviada.
     * @param addr O endereço IP de destino.
     * @param port A porta de destino.
     * @throws Exception Se ocorrer um erro de I/O.
     */
    private static void send(DatagramSocket socket, String msg, InetAddress addr, int port) throws Exception {
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr, port);
        socket.send(packet);
    }
}