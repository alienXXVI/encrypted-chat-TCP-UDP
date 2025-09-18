import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.util.Base64;

public class RSAUtils {

    // Gera um par de chaves RSA (pública + privada)
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // 2048 bits
        return keyGen.generateKeyPair();
    }

    // Converte chave pública para String Base64
    public static String keyToString(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Converte String Base64 para chave pública
    public static PublicKey stringToPublicKey(String keyStr) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(keyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    // Criptografa uma mensagem com a chave pública do destinatário
    public static byte[] encrypt(String message, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes("UTF-8"));
    }

    // Descriptografa uma mensagem com a chave privada do destinatário
    public static String decrypt(byte[] encrypted, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, "UTF-8");
    }

    // Assina uma mensagem com a chave privada
    public static byte[] sign(String message, PrivateKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(message.getBytes("UTF-8"));
        return signature.sign();
    }

    // Verifica assinatura com a chave pública
    public static boolean verify(String message, byte[] sig, PublicKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(message.getBytes("UTF-8"));
        return signature.verify(sig);
    }
}
