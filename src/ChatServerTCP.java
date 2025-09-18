import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

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
                        sendToUser(target, msg);
                    } else if (msg.startsWith("@")) {
                        // Mensagem privada não criptografada
                        String[] parts = msg.split(" ", 2);
                        String target = parts[0].substring(1);
                        String text = parts.length > 1 ? parts[1] : "";
                        sendToUser(target, "[Privado] " + username + ": " + text);
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

        private void sendToUser(String user, String message) throws IOException {
            synchronized (clients) {
                Socket s = clients.get(user);
                if (s != null) {
                    PrintWriter writer = new PrintWriter(s.getOutputStream(), true);
                    writer.println(message);
                }
            }
        }

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
