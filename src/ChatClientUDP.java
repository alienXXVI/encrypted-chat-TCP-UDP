import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.Base64;

public class ChatClientUDP {
    private static final String SERVER_IP = "localhost";
    private static final int SERVER_PORT = 50001;
    private static final int BUFFER_SIZE = 8192;

    private static Map<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();
    private static KeyPair keyPair;
    private static PrivateKey myPrivate;

    public static void main(String[] args) throws Exception {
        DatagramSocket socket = new DatagramSocket();
        Scanner scanner = new Scanner(System.in);

        keyPair = RSAUtils.generateKeyPair();
        PublicKey myPublic = keyPair.getPublic();
        myPrivate = keyPair.getPrivate();

        System.out.print("Digite seu nome de usuario: ");
        String username = scanner.nextLine();

        send(socket, "REGISTRO:" + username + ":" + RSAUtils.keyToString(myPublic));

        // Thread de recepção
        new Thread(() -> {
            byte[] buffer = new byte[BUFFER_SIZE];
            while (!socket.isClosed()) {
                try {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);
                    String msg = new String(packet.getData(), 0, packet.getLength());

                    if (msg.startsWith("LISTA_KEYS:")) {
                        String[] lines = msg.split("\n");
                        for (String line : lines) {
                            if (line.trim().isEmpty() || line.startsWith("LISTA_KEYS")) continue;
                            String[] kv = line.split(":", 2);
                            String user = kv[0];
                            PublicKey key = RSAUtils.stringToPublicKey(kv[1]);
                            publicKeyCache.put(user, key);
                        }
                        // System.out.println("[INFO] Lista inicial de chaves recebida.");
                    } else if (msg.startsWith("NEWKEY:")) {
                        String[] parts = msg.split(":", 3);
                        String user = parts[1];
                        PublicKey key = RSAUtils.stringToPublicKey(parts[2]);
                        publicKeyCache.put(user, key);
                        // System.out.println("[INFO] Nova chave recebida de " + user);
                    } else if (msg.startsWith("PRIVADO:") || msg.startsWith("ENCRYPTED:")) {
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
                                    System.out.println("[ERRO] Assinatura invalida de " + from);
                            } else {
                                System.out.println("[ERRO] Chave publica de " + from + " nao encontrada.");
                            }
                        } else {
                            String text = parts[3];
                            System.out.println("[Privado] " + from + ": " + text);
                        }
                    } else {
                        System.out.println(msg);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    break;
                }
            }
        }).start();

        // Loop de envio
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
                    PublicKey destKey = publicKeyCache.get(target);
                    if (destKey == null) {
                        System.out.println("[ERRO] Nao tenho a chave publica de " + target);
                        continue;
                    }

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
