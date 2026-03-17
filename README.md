# Encrypted Chat TCP/UDP

## Description
This project is a secure, distributed chat application that demonstrates network communication using both **TCP (Transmission Control Protocol)** and **UDP (User Datagram Protocol)**. It prioritizes security by implementing **RSA cryptography** to ensure message confidentiality and digital signatures to verify the authenticity of the senders.

## Technologies
-   **Java SE** (Socket and DatagramSocket API)
-   **RSA Cryptography** (2048-bit keys)
-   **Digital Signatures** (SHA256withRSA)
-   **TCP/IP & UDP Protocols**

## Features
-   **Dual Protocol Support:** Includes independent implementations for both TCP and UDP communication.
-   **End-to-End Encryption:** Uses RSA public keys to encrypt private messages, ensuring only the intended recipient can read them.
-   **Identity Verification:** Employs digital signatures to prevent message tampering and impersonation.
-   **Multi-Client Handling:** The servers manage multiple simultaneous connections and maintain a registry of active users and their public keys.
-   **Command System:** Built-in commands for listing active users (`!list`) and exiting the chat (`!exit`).

## How to Run

### 1. Compile the Project
Navigate to the `src` directory and compile all Java files:

    javac *.java

### 2. Start the Server
Run either the TCP or UDP server version:
-   **TCP:** `java ChatServerTCP`
-   **UDP:** `java ChatServerUDP`

### 3. Run the Clients

Open multiple terminal windows to simulate different users and run:

-   **TCP:** `java ChatClientTCP`
-   **UDP:** `java ChatClientUDP`
    

### 4. Chatting Securely

-   **Global Message:** Just type your message and press Enter.
-   **Private Message:** Use `@username message`.
-   **Encrypted/Signed Private Message:** Use `@username SECURE message`.

## Project Structure

-   **`ChatServerTCP.java` & `ChatServerUDP.java`**: Manage client connections, coordinate message broadcasting, and store public keys.
-   **`ChatClientTCP.java` & `ChatClientUDP.java`**: Handle user input, key generation, and the asynchronous receiving of messages.
-   **`RSAUtils.java`**: A utility class containing the logic for generating 2048-bit RSA keys, encrypting/decrypting data, and signing/verifying messages.
-   **`.gitignore`**: Configured to ignore compiled `.class` files and IDE-specific folders.
-   **`README.md`**: Project documentation.

## What I Learned

-   **Network Fundamentals:** Differences between stream-oriented (TCP) and packet-oriented (UDP) communication in a real-world application.
-   **Asymmetric Cryptography:** Practical implementation of RSA for secure key exchange and data protection.
-   **Concurrency:** Using Java Threads to handle simultaneous I/O operations without blocking the user interface.
-   **Data Serialization:** Encoding binary keys and encrypted data into Base64 strings for safe transmission over text-based protocols.


## Future Improvements

-   **Key Persistence:** Store public keys in a database or file instead of volatile memory.
-   **GUI:** Develop a graphical user interface to replace the current command-line interface.
-   **Hybrid Encryption:** Implement AES for message encryption and use RSA only for exchanging the AES session keys to improve performance for large messages.
