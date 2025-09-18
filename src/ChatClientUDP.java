import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class ChatClientUDP {
    private static final int SERVER_PORT = 50001;
    private static final String SERVER_IP = "localhost";
    private static final int BUFFER_SIZE = 4096;

    public static void main(String[] args) throws Exception {
        DatagramSocket socket = new DatagramSocket();
        Scanner scanner = new Scanner(System.in);

        KeyPair clientKeyPair = RSAUtils.generateKeyPair();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

        System.out.print("Digite seu nome de usuário: ");
        String username = scanner.nextLine();

        send(socket, "REGISTRO:" + username + ":" + RSAUtils.keyToString(clientPublicKey));

        new Thread(() -> {
            byte[] buffer = new byte[BUFFER_SIZE];
            while (!socket.isClosed()) {
                try {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);
                    String msg = new String(packet.getData(), 0, packet.getLength());

                    if (msg.startsWith("ENCRYPTED:")) {
                        String[] parts = msg.split(":", 5);
                        String fromUser = parts[1];
                        byte[] encryptedMsg = Base64.getDecoder().decode(parts[2]);
                        byte[] signature = Base64.getDecoder().decode(parts[3]);
                        PublicKey senderKey = RSAUtils.stringToPublicKey(parts[4]);

                        try {
                            String decrypted = RSAUtils.decrypt(encryptedMsg, clientPrivateKey);
                            boolean valid = RSAUtils.verify(decrypted, signature, senderKey);

                            if (valid) {
                                System.out.println("[Privado-SECURE] " + fromUser + ": " + decrypted);
                            } else {
                                System.out.println("[ERRO] Assinatura inválida de " + fromUser);
                            }
                        } catch (Exception e) {
                            System.err.println("[ERRO] Falha ao processar mensagem criptografada.");
                        }
                    } else {
                        System.out.println(msg);
                    }
                } catch (Exception e) {
                    break;
                }
            }
        }).start();

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
                if (parts.length >= 3 && parts[1].equalsIgnoreCase("SECURE")) {
                    String target = parts[0].substring(1);
                    String message = parts[2];

                    byte[] signature = RSAUtils.sign(message, clientPrivateKey);
                    String packet = "PRIVADO:" + username + ":" + target + ":SECURE " +
                            Base64.getEncoder().encodeToString(signature) + " " + message;
                    send(socket, packet);
                } else {
                    String target = input.substring(1, input.indexOf(" "));
                    String msg = input.substring(input.indexOf(" ") + 1);
                    send(socket, "PRIVADO:" + username + ":" + target + ":" + msg);
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
