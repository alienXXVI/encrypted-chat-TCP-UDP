import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Cliente de chat TCP que se conecta a um servidor, envia e recebe mensagens.
 * Suporta comunicação de texto simples, mensagens criptografadas e comandos.
 * Gerencia a geração de chaves RSA e o cache de chaves públicas de outros usuários.
 *
 * @author [Seu Nome]
 * @version 1.0
 */
public class ChatClientTCP {
    /**
     * Ponto de entrada principal do cliente. Gerencia a conexão, a troca de chaves,
     * o loop de envio e a thread de recebimento.
     *
     * @param args Argumentos da linha de comando (não utilizados).
     * @throws Exception Se ocorrer um erro durante a conexão ou I/O.
     */
    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 50000);

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        KeyPair clientKeyPair = RSAUtils.generateKeyPair();
        PublicKey clientPublicKey = clientKeyPair.getPublic();
        PrivateKey clientPrivateKey = clientKeyPair.getPrivate();

        Map<String, PublicKey> keyCache = new HashMap<>();

        System.out.print("Digite seu nome de usuario: ");
        String username = keyboard.readLine();
        out.println("REGISTRO:" + username + ":" + RSAUtils.keyToString(clientPublicKey));

        // Thread para receber mensagens do servidor.
        new Thread(() -> {
            String serverMsg;
            try {
                while ((serverMsg = in.readLine()) != null) {
                    if (serverMsg.startsWith("PUBKEYRESP:")) {
                        String[] parts = serverMsg.split(":", 3);
                        String user = parts[1];
                        PublicKey pubKey = RSAUtils.stringToPublicKey(parts[2]);
                        keyCache.put(user, pubKey);
                        // System.out.println("[INFO] Chave pública de " + user + " recebida.");
                    } else if (serverMsg.startsWith("ENCRYPTED:")) {
                        String[] parts = serverMsg.split(":", 3);
                        String fromUser = parts[1];
                        byte[] encrypted = Base64.getDecoder().decode(parts[2]);
                        String decrypted = RSAUtils.decrypt(encrypted, clientPrivateKey);
                        System.out.println("[Privado-SECURE] " + fromUser + ": " + decrypted);
                    } else {
                        System.out.println(serverMsg);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        // Loop de envio
        String userInput;
        while ((userInput = keyboard.readLine()) != null) {
            if (userInput.equalsIgnoreCase("!list")) {
                out.println("!list");
            } else if (userInput.equalsIgnoreCase("!exit")) {
                out.println("!exit");
                break;
            } else if (userInput.startsWith("@")) {
                String[] parts = userInput.split(" ", 3);
                String targetUser = parts[0].substring(1);
                boolean secure = parts.length >= 3 && parts[1].equalsIgnoreCase("SECURE");
                String message = secure ? parts[2] : userInput.substring(userInput.indexOf(" ") + 1);

                if (secure) {
                    PublicKey targetKey = keyCache.get(targetUser);
                    if (targetKey == null) {
                        // System.out.println("[INFO] Solicitando chave pública de " + targetUser + "...");
                        out.println("REQKEY:" + targetUser);
                        // Aguarda a chave ser recebida na thread de recebimento
                        while (!keyCache.containsKey(targetUser)) {
                            Thread.sleep(50);
                        }
                        targetKey = keyCache.get(targetUser);
                    }
                    byte[] encrypted = RSAUtils.encrypt(message, targetKey);
                    out.println("ENCRYPTED:" + targetUser + ":" + Base64.getEncoder().encodeToString(encrypted));
                } else {
                    out.println(userInput);
                }
            } else {
                out.println(userInput);
            }
        }

        socket.close();
    }
}