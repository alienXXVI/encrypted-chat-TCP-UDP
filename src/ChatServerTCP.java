import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;

public class ChatServerTCP {
    private static final int PORT = 50000;
    private static Map<String, Socket> clients = new HashMap<>();
    private static Map<String, PublicKey> clientPublicKeys = new HashMap<>();

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Servidor TCP escutando na porta " + PORT);

        while (true) {
            Socket socket = serverSocket.accept();
            new Thread(new ClientHandler(socket)).start();
        }
    }

    static class ClientHandler implements Runnable {
        private Socket socket;
        private String username;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                // Recebe REGISTRO do cliente (username + publicKey)
                String regMsg = in.readLine();
                if (regMsg != null && regMsg.startsWith("REGISTRO:")) {
                    String[] parts = regMsg.split(":", 3);
                    username = parts[1];
                    PublicKey clientPublicKey = RSAUtils.stringToPublicKey(parts[2]);

                    synchronized (clients) {
                        clients.put(username, socket);
                        clientPublicKeys.put(username, clientPublicKey);
                    }

                    broadcast(username + " entrou no chat.", null, null);
                }

                String message;
                while ((message = in.readLine()) != null) {
                    if (message.equalsIgnoreCase("!list")) {
                        sendUserList(out);
                    } else if (message.equalsIgnoreCase("!exit")) {
                        break;
                    } else if (message.startsWith("@")) {
                        // Mensagem privada
                        String[] parts = message.split(" ", 4); // @alvo SECURE assinatura texto...
                        String targetUser = parts[0].substring(1);
                        boolean secure = parts.length >= 4 && parts[1].equalsIgnoreCase("SECURE");
                        String text;
                        String signatureB64 = null;

                        if (secure) {
                            signatureB64 = parts[2];
                            // Reconstrói a mensagem inteira depois da assinatura
                            int idx = message.indexOf(parts[3]);
                            text = message.substring(idx);
                        } else {
                            text = message.substring(message.indexOf(" ") + 1);
                        }

                        System.out.println("[Privado" + (secure ? "-SECURE] " : "] ") + username + " para " + targetUser + ": " + text);
                        sendToUser(targetUser, "[Privado] " + username + ": " + text, secure, signatureB64);
                    } else {
                        // Broadcast simples
                        broadcast("[Todos] " + username + ": " + message, null, null);
                    }
                }

                socket.close();
                synchronized (clients) {
                    clients.remove(username);
                    clientPublicKeys.remove(username);
                }
                broadcast(username + " saiu do chat.", null, null);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void broadcast(String message, String signatureB64, PublicKey senderKey) throws IOException {
            synchronized (clients) {
                for (String user : clients.keySet()) {
                    if (!user.equals(username)) {
                        sendToUser(user, message, signatureB64 != null, signatureB64);
                    }
                }
            }
            System.out.println(message);
        }

        private void sendToUser(String user, String message, boolean secure, String signatureB64) throws IOException {
            synchronized (clients) {
                Socket s = clients.get(user);
                PublicKey destPublicKey = clientPublicKeys.get(user);
                if (s != null) {
                    PrintWriter writer = new PrintWriter(s.getOutputStream(), true);
                    if (secure && destPublicKey != null && signatureB64 != null) {
                        try {
                            // Envia apenas a mensagem original (sem prefixo "[Privado] aliana: ")
                            String originalMessage = message.substring(message.indexOf(":") + 2); // remove "[Privado] username: "

                            byte[] encryptedMsg = RSAUtils.encrypt(originalMessage, destPublicKey);

                            PublicKey senderKey = clientPublicKeys.get(username);
                            String packet = "ENCRYPTED:" + username + ":" +
                                    Base64.getEncoder().encodeToString(encryptedMsg) + ":" +
                                    signatureB64 + ":" +
                                    RSAUtils.keyToString(senderKey);

                            writer.println(packet);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        writer.println(message);
                    }
                }
            }
            // System.out.println("Mensagem enviada para " + user + ": " + message);
        }

        private void sendUserList(PrintWriter out) {
            synchronized (clients) {
                StringBuilder userList = new StringBuilder("Usuários conectados:\n");
                for (String user : clients.keySet()) {
                    userList.append("- ").append(user).append("\n");
                }
                out.println(userList.toString());
            }
        }
    }
}
