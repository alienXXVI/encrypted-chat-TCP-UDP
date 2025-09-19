import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class ChatClientUDP {
    private static final String SERVER_IP = "localhost";
    private static final int SERVER_PORT = 50001;
    private static final int BUFFER_SIZE = 8192;

    public static void main(String[] args) throws Exception {
        DatagramSocket socket = new DatagramSocket();
        Scanner scanner = new Scanner(System.in);

        Map<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();

        KeyPair keyPair = RSAUtils.generateKeyPair();
        PublicKey myPublic = keyPair.getPublic();
        PrivateKey myPrivate = keyPair.getPrivate();

        System.out.print("Digite seu nome de usuario: ");
        String username = scanner.nextLine();

        // Registro no servidor
        send(socket, "REGISTRO:" + username + ":" + RSAUtils.keyToString(myPublic));
        // Solicita lista de usuários ativos
        send(socket, "LISTAR_USUARIOS:");

        // Thread para receber mensagens
        new Thread(() -> {
            byte[] buffer = new byte[BUFFER_SIZE];
            while (!socket.isClosed()) {
                try {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);
                    String msg = new String(packet.getData(), 0, packet.getLength());

                    // Recebe lista de usuários
                    if (msg.startsWith("Usuarios registrados:")) {
                        String[] lines = msg.split("\n");
                        for (String line : lines) {
                            line = line.trim();
                            if (line.isEmpty() || line.startsWith("Usuarios")) continue;
                            String user = line.substring(2); // remove "- "
                            if (!user.equals(username) && !publicKeyCache.containsKey(user)) {
                                send(socket, "REQKEY:" + user);
                            }
                        }
                    }

                    // Recebe chave pública
                    else if (msg.startsWith("PUBKEYRESP:")) {
                        String[] parts = msg.split(":", 3);
                        String user = parts[1];
                        PublicKey key = RSAUtils.stringToPublicKey(parts[2]);
                        publicKeyCache.put(user, key);
                        System.out.println("[INFO] Chave publica de " + user + " recebida.");
                    }

                    // Recebe mensagens privadas
                    else if (msg.startsWith("PRIVADO:") || msg.startsWith("ENCRYPTED:")) {
                        String[] parts = msg.split(":", 6);
                        String from = parts[1];
                        boolean secure = parts[3].equalsIgnoreCase("SECURE");

                        if (secure) {
                            byte[] signature = Base64.getDecoder().decode(parts[4]);
                            byte[] encrypted = Base64.getDecoder().decode(parts[5]);
                            PublicKey senderKey = publicKeyCache.get(from);

                            if (senderKey != null) {
                                String decrypted = RSAUtils.decrypt(encrypted, myPrivate);
                                boolean valid = RSAUtils.verify(decrypted, signature, senderKey);
                                if (valid)
                                    System.out.println("[Privado-SECURE] " + from + ": " + decrypted);
                                else
                                    System.out.println("[ERRO] Assinatura inválida de " + from);
                            } else {
                                System.out.println("[ERRO] Chave pública de " + from + " não encontrada.");
                            }
                        } else {
                            String text = parts[3];
                            System.out.println("[Privado] " + from + ": " + text);
                        }
                    }

                    // Mensagens gerais
                    else {
                        System.out.println(msg);
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                    break;
                }
            }
        }).start();

        // Loop principal de envio
        while (true) {
            String input = scanner.nextLine();

            if (input.equalsIgnoreCase("!list")) {
                send(socket, "LISTAR_USUARIOS:");
            } else if (input.equalsIgnoreCase("!exit")) {
                send(socket, "SAIR:" + username);
                Thread.sleep(200);
                socket.close();
                break;
            } else if (input.startsWith("@")) {
                String[] parts = input.split(" ", 3);
                String target = parts[0].substring(1);
                boolean secure = parts.length >= 3 && parts[1].equalsIgnoreCase("SECURE");
                String msgText = secure ? parts[2] : input.substring(input.indexOf(" ") + 1);

                if (secure) {
                    // Se não temos a chave, pedimos e aguardamos
                    if (!publicKeyCache.containsKey(target)) {
                        send(socket, "REQKEY:" + target);
                        while (!publicKeyCache.containsKey(target)) {
                            Thread.sleep(50); // espera chegar a chave
                        }
                    }

                    PublicKey destKey = publicKeyCache.get(target);
                    byte[] encrypted = RSAUtils.encrypt(msgText, destKey);
                    byte[] signature = RSAUtils.sign(msgText, keyPair.getPrivate());

                    String packet = "PRIVADO:" + username + ":" + target + ":SECURE:" +
                            Base64.getEncoder().encodeToString(signature) + ":" +
                            Base64.getEncoder().encodeToString(encrypted);
                    send(socket, packet);

                } else {
                    send(socket, "PRIVADO:" + username + ":" + target + ":" + msgText);
                }
            } else {
                send(socket, "BROADCAST:" + username + ":" + input);
            }
        }
    }

    private static void send(DatagramSocket socket, String msg) throws Exception {
        InetAddress addr = InetAddress.getByName(SERVER_IP);
        byte[] data = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(data, data.length, addr, SERVER_PORT);
        socket.send(packet);
    }
}
