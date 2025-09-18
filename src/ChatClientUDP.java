import java.net.*;
import java.util.Scanner;

public class ChatClientUDP {
    // Configurações do servidor: IP e porta
    private static final int SERVER_PORT = 50001;
    private static final String SERVER_IP = "localhost";
    private static final int BUFFER_SIZE = 1024;

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        // Cria um DatagramSocket, que é usado para enviar e receber pacotes
        // Diferente do TCP, não há uma conexão persistente com o servidor
        DatagramSocket socket = new DatagramSocket();

        System.out.print("Digite seu nome de usuario: ");
        String username = scanner.nextLine();

        // Envia uma mensagem de registro para o servidor
        // Isso é necessário em UDP para que o servidor saiba o endereço e a porta do cliente para enviar mensagens de volta
        sendMessage(socket, "REGISTRO:" + username);
        // Pequena pausa para garantir que o servidor processe o registro antes de enviar outras mensagens
        Thread.sleep(200);

        // Cria uma thread separada para receber mensagens do servidor
        // Isso permite que o cliente continue digitando e enviando mensagens enquanto escuta por novas mensagens do servidor
        new Thread(() -> {
            byte[] buffer = new byte[BUFFER_SIZE];
            // Loop infinito para receber mensagens
            while (!socket.isClosed()) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                try {
                    // Bloqueia a execução até que um pacote seja recebido
                    socket.receive(packet);
                    // Converte os dados do pacote para uma String e exibe no console
                    String msg = new String(packet.getData(), 0, packet.getLength());
                    System.out.println(msg);
                } catch (SocketException e) {
                    // Esta exceção é esperada e ignorada quando o socket é fechado pela thread principal (ao sair do chat)
                    break; // Sai do loop e termina a thread
                } catch (Exception e) {
                    // Captura outras exceções de forma geral
                    e.printStackTrace();
                }
            }
        }).start();

        // Loop principal para ler a entrada do usuário e enviar mensagens
        while (true) {
            String input = scanner.nextLine();
            if (input.equalsIgnoreCase("!list")) {
                // Envia o comando para listar usuários ao servidor
                sendMessage(socket, "LISTAR_USUARIOS:");
            }
            else if (input.equalsIgnoreCase("!exit")) {
                // Envia o comando de saída ao servidor
                sendMessage(socket, "SAIR:" + username);
                // Pausa para dar tempo ao pacote de saída ser enviado antes de fechar o socket.
                Thread.sleep(200);
                // Sai do loop, encerrando o programa
                socket.close();
                break;
            }
            else if (input.startsWith("@")) {
                // Lida com mensagens privadas
                int space = input.indexOf(" ");
                if (space == -1) {
                    System.out.println("Formato inválido. Use: @usuario mensagem");
                    continue;
                }
                String to = input.substring(1, space);
                String msg = input.substring(space + 1);
                sendMessage(socket, "PRIVADO:" + username + ":" + to + ":" + msg);
            } else {
                // Lida com mensagens de broadcast para todos
                sendMessage(socket, "BROADCAST:" + username + ":" + input);
            }
        }
    }

    // Método auxiliar para enviar uma mensagem ao servidor (DatagramPacket)
    private static void sendMessage(DatagramSocket socket, String msg) throws Exception {
        byte[] data = msg.getBytes();
        InetAddress serverAddress = InetAddress.getByName(SERVER_IP);
        // Cria um pacote com os dados, o endereço e a porta do servidor
        DatagramPacket packet = new DatagramPacket(data, data.length, serverAddress, SERVER_PORT);
        // Envia o pacote de forma "fire-and-forget" - Não há garantia de entrega
        socket.send(packet);
    }
}
