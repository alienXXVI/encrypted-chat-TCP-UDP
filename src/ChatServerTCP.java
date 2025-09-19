import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

/**
 * Servidor de chat TCP que aceita conexões de múltiplos clientes,
 * gerencia a lista de usuários e encaminha mensagens.
 * Suporta mensagens de texto simples e mensagens criptografadas
 * com RSA, além de comandos de chat como listar usuários e sair.
 *
 * @author [Seu Nome]
 * @version 1.0
 */
public class ChatServerTCP {
    private static final int PORT = 50000;
    private static Map<String, Socket> clients = new HashMap<>();
    private static Map<String, PublicKey> clientPublicKeys = new HashMap<>();

    /**
     * Ponto de entrada principal do servidor. Inicia o ServerSocket
     * e entra em um loop infinito para aceitar novas conexões de clientes.
     * Para cada cliente, uma nova thread ClientHandler é iniciada.
     *
     * @param args Argumentos da linha de comando (não utilizados).
     * @throws IOException Se ocorrer um erro de I/O ao iniciar o servidor.
     */
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor TCP escutando na porta " + PORT);

        while (true) {
            Socket socket = serverSocket.accept();
            new Thread(new ClientHandler(socket)).start();
        }
    }

    /**
     * Classe interna que lida com a comunicação individual de cada cliente em uma thread separada.
     * Responsável por ler as mensagens, processar comandos e encaminhar mensagens.
     */
    static class ClientHandler implements Runnable {
        private Socket socket;
        private String username;

        /**
         * Construtor para o ClientHandler.
         *
         * @param socket O socket da conexão com o cliente.
         */
        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        /**
         * Lógica principal da thread do cliente. Gerencia o registro, a troca de chaves,
         * o processamento de mensagens e a desconexão.
         */
        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                // Registro do cliente
                String regMsg = in.readLine();
                if (regMsg != null && regMsg.startsWith("REGISTRO:")) {
                    String[] parts = regMsg.split(":", 3);
                    username = parts[1];
                    PublicKey pubKey = RSAUtils.stringToPublicKey(parts[2]);

                    synchronized (clients) {
                        clients.put(username, socket);
                        clientPublicKeys.put(username, pubKey);
                    }
                    broadcast(username + " entrou no chat.", true, null);
                }

                String msg;
                while ((msg = in.readLine()) != null) {

                    if (msg.equalsIgnoreCase("!list")) {
                        sendUserList(out);

                    } else if (msg.equalsIgnoreCase("!exit")) {
                        break;
                        
                    } else if (msg.startsWith("REQKEY:")) {
                        String target = msg.substring(7);
                        PublicKey targetKey = clientPublicKeys.get(target);
                        if (targetKey != null) {
                            out.println("PUBKEYRESP:" + target + ":" + RSAUtils.keyToString(targetKey));
                        } else {
                            out.println("PUBKEYRESPERR:" + target);
                        }

                    } else if (msg.startsWith("ENCRYPTED:")) {
                        String[] parts = msg.split(":", 3);
                        String target = parts[1];
                        String encryptedContent = parts[2];

                        sendToUser(target, "ENCRYPTED:" + username + ":" + encryptedContent);

                    } else if (msg.startsWith("@")) {
                        String[] parts = msg.split(" ", 2);
                        String target = parts[0].substring(1);
                        String text = parts.length > 1 ? parts[1] : "";
                        
                        sendToUser(target, "[Privado] " + username + ": " + text);
                        System.out.println("[Privado] " + username + " para " + target + ": " + text);
                    } else {
                        broadcast("[Todos] " + username + ": " + msg, false, username);
                    }
                }

                socket.close();
                synchronized (clients) {
                    clients.remove(username);
                    clientPublicKeys.remove(username);
                }
                broadcast(username + " saiu do chat.", true, null);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        /**
         * Envia uma mensagem de broadcast para todos os clientes conectados.
         *
         * @param message A mensagem a ser enviada.
         * @param notifyAll Se true, notifica a todos; se false, exclui o remetente.
         * @param excludeUser Nome do usuário a ser excluído do broadcast (nulo para incluir todos).
         * @throws IOException Se ocorrer um erro de I/O ao enviar a mensagem.
         */
        private void broadcast(String message, boolean notifyAll, String excludeUser) throws IOException {
            synchronized (clients) {
                for (Map.Entry<String, Socket> entry : clients.entrySet()) {
                    if (!notifyAll && entry.getKey().equals(excludeUser)) continue;
                    PrintWriter writer = new PrintWriter(entry.getValue().getOutputStream(), true);
                    writer.println(message);
                }
            }
            System.out.println(message);
        }

        /**
         * Envia uma mensagem para um usuário específico.
         *
         * @param user O nome de usuário do destinatário.
         * @param message A mensagem a ser enviada.
         * @throws IOException Se ocorrer um erro de I/O.
         */
        private void sendToUser(String user, String message) throws IOException {
            synchronized (clients) {
                Socket s = clients.get(user);
                if (s != null) {
                    PrintWriter writer = new PrintWriter(s.getOutputStream(), true);
                    writer.println(message);
                }
            }
        }

        /**
         * Envia a lista de usuários conectados para o cliente que a solicitou.
         *
         * @param out O fluxo de saída para o cliente solicitante.
         */
        private void sendUserList(PrintWriter out) {
            synchronized (clients) {
                StringBuilder sb = new StringBuilder("Usuarios conectados:\n");
                for (String u : clients.keySet()) {
                    sb.append("- ").append(u).append("\n");
                }
                out.println(sb.toString());
            }
        }
    }
}