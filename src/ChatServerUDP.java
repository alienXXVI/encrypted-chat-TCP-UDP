import java.net.*;
import java.util.*;

public class ChatServerUDP {
    // Porta que o servidor irá escutar por datagramas
    private static final int PORT = 50001;
    // O tamanho do buffer para receber os pacotes
    private static final int BUFFER_SIZE = 1024;
    // Um mapa que armazena os clientes, associando o nome de usuário ao seu endereço e porta
    // Em UDP, o servidor precisa manter este mapa para saber para onde enviar as respostas
    private static Map<String, InetSocketAddress> clients = new HashMap<>();

    public static void main(String[] args) throws Exception {
        // Cria o DatagramSocket, que é o "ponto de escuta" para pacotes UDP na porta especificada
        DatagramSocket socket = new DatagramSocket(PORT);
        byte[] buffer = new byte[BUFFER_SIZE];
        System.out.println("Servidor UDP pronto na porta " + PORT);

        // Loop infinito para receber pacotes de datagrama
        while (true) {
            // Cria um DatagramPacket vazio para armazenar o pacote recebido
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            // Bloqueia a execução até que um pacote seja recebido
            socket.receive(packet);

            // Converte os dados do pacote para uma String
            String received = new String(packet.getData(), 0, packet.getLength());
            // Obtém o endereço e a porta do remetente do pacote
            InetAddress address = packet.getAddress();
            int port = packet.getPort();
            
            // Verifica se a mensagem é um comando para listar usuários
            if (received.startsWith("LISTAR_USUARIOS:")) {
                String userList = "Usuários registrados:\n";
                // Percorre a lista de clientes registrados no mapa
                for (String user : clients.keySet()) {
                    userList += "- " + user + "\n";
                }
                byte[] data = userList.getBytes();
                // Envia a lista de volta para o cliente que a solicitou
                DatagramPacket responsePacket = new DatagramPacket(data, data.length, address, port);
                socket.send(responsePacket);
                continue; // Processa o próximo pacote
            }

            // Verifica se a mensagem é um comando de saída
            if (received.startsWith("SAIR:")) {
                String username = received.substring(5).trim();
                // Remove o cliente do mapa, já que ele saiu
                clients.remove(username);

                String leaveMsg = username + " saiu do chat.";
                // Notifica todos os outros clientes que este usuário saiu
                broadcast(socket, leaveMsg);
                continue; // Processa o próximo pacote
            }

            // Verifica se a mensagem é um comando de registro
            if (received.startsWith("REGISTRO:")) {
                String username = received.substring(9).trim();
                // Adiciona o cliente ao mapa com seu endereço e porta
                clients.put(username, new InetSocketAddress(address, port));

                String joinMsg = username + " entrou no chat.";
                // Notifica todos os outros clientes que este usuário entrou
                broadcast(socket, joinMsg);

                continue; // Processa o próximo pacote
            }

            // Verifica se a mensagem é um broadcast para todos
            if (received.startsWith("BROADCAST:")) {
                String[] partes = received.split(":", 3);
                String from = partes[1];
                String mensagem = partes[2];
                String msgFinal = "[Todos] " + from + ": " + mensagem;

                // Envia a mensagem para todos os clientes registrados
                broadcast(socket, msgFinal);
                continue; // Processa o próximo pacote
            }

            // Verifica se a mensagem é privada
            if (received.startsWith("PRIVADO:")) {
                try {
                    String[] partes = received.split(":", 4);
                    if (partes.length < 4) {
                        System.err.println("Formato inválido de mensagem privada: " + received);
                        continue;
                    }

                    String from = partes[1];
                    String to = partes[2];
                    String mensagem = partes[3];

                    // Procura o destinatário no mapa de clientes
                    InetSocketAddress dest = clients.get(to);
                    if (dest != null) {
                        String msgFinal = "[Privado] " + from + ": " + mensagem;
                        byte[] data = msgFinal.getBytes();
                        // Envia a mensagem diretamente para o destinatário
                        socket.send(new DatagramPacket(data, data.length, dest));
                        System.out.println(msgFinal);
                    } else {
                        System.out.println("Usuário " + to + " não encontrado para mensagem privada.");
                    }

                } catch (Exception e) {
                    System.err.println("Erro ao processar mensagem privada: " + e);
                    e.printStackTrace();
                }
            }
        }
    }

    // Envia uma mensagem de broadcast para todos os clientes registrados no mapa
    private static void broadcast(DatagramSocket socket, String message) throws Exception {
        // Percorre todos os clientes no mapa
        for (InetSocketAddress dest : clients.values()) {
            byte[] data = message.getBytes();
            // Cria e envia um novo pacote para cada cliente
            socket.send(new DatagramPacket(data, data.length, dest));
        }
        System.out.println(message);
    }
}
