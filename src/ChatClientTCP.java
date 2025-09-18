import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

public class ChatClientTCP {
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 50000);

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        // Gera par de chaves do cliente
        KeyPair clientKeyPair = RSAUtils.generateKeyPair();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

        System.out.print("Digite seu nome de usuário: ");
        String username = keyboard.readLine();
        // Registra o usuário enviando nome de usuário e chave pública
        out.println("REGISTRO:" + username + ":" + RSAUtils.keyToString(clientPublicKey));

        // Thread para processar mensagens recebidas
        new Thread(() -> {
            String serverMsg;
            try {
                while ((serverMsg = in.readLine()) != null) {
                    if (serverMsg.startsWith("ENCRYPTED:")) {
                        // ENCRYPTED:remetente:msgCripto:assinatura:remetentePublicKey
                        String[] parts = serverMsg.split(":", 5);
                        String fromUser = parts[1];
                        byte[] encryptedMsg = Base64.getDecoder().decode(parts[2]);
                        byte[] signature = Base64.getDecoder().decode(parts[3]);
                        PublicKey senderPublicKey = RSAUtils.stringToPublicKey(parts[4]);

                        try {
                            String decrypted = RSAUtils.decrypt(encryptedMsg, clientPrivateKey);

                            boolean valid = RSAUtils.verify(decrypted, signature, senderPublicKey);
                            if (valid) {
                                System.out.println("[Privado-SECURE] " + fromUser + ": " + decrypted);
                            } else {
                                System.out.println("[ERRO] Assinatura inválida na mensagem de " + fromUser);
                            }
                        } catch (Exception e) {
                            System.err.println("[ERRO] Falha ao processar mensagem criptografada: " + e.getMessage());
                        }
                    } else {
                        System.out.println(serverMsg);
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }).start();

        // Loop principal de envio
        String userInput;
        while ((userInput = keyboard.readLine()) != null) {
            if (userInput.equalsIgnoreCase("!list")) {
                out.println("!list");
            } else if (userInput.equalsIgnoreCase("!exit")) {
                out.println("!exit");
                break;
            } else {
                if (userInput.startsWith("@")) {
                    String[] parts = userInput.split(" ", 3);
                    if (parts.length >= 3 && parts[1].equalsIgnoreCase("SECURE")) {
                        // message = parts[2]
                        String message = parts[2];
                        byte[] signature = RSAUtils.sign(message, clientPrivateKey);
                        String packet = "@" + parts[0].substring(1) + " SECURE " +
                                        Base64.getEncoder().encodeToString(signature) + " " + message;
                        out.println(packet);
                    } else {
                        out.println(userInput); // mensagem privada comum
                    }
                } else {
                    out.println(userInput); // broadcast
                }
            }
        }
        socket.close();
    }
}
