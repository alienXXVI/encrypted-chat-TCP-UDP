import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.util.Base64;

/**
 * Classe utilitária para operações de criptografia e gerenciamento de chaves RSA.
 * Fornece métodos estáticos para geração de chaves, criptografia,
 * descriptografia, assinatura e verificação.
 *
 * @author [Seu Nome]
 * @version 1.0
 */
public class RSAUtils {

    /**
     * Gera um novo par de chaves RSA.
     *
     * @return Um objeto KeyPair contendo a chave pública e a chave privada.
     * @throws NoSuchAlgorithmException Se o algoritmo RSA não estiver disponível.
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    /**
     * Converte uma chave pública para uma String codificada em Base64.
     *
     * @param key A chave pública a ser convertida.
     * @return A chave em formato de String.
     */
    public static String keyToString(PublicKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Converte uma String codificada em Base64 de volta para um objeto PublicKey.
     *
     * @param keyStr A String da chave a ser convertida.
     * @return O objeto PublicKey.
     * @throws Exception Se ocorrer um erro durante a conversão.
     */
    public static PublicKey stringToPublicKey(String keyStr) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(keyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * Criptografa uma mensagem usando a chave pública do destinatário.
     *
     * @param message A mensagem em texto simples.
     * @param key A chave pública do destinatário.
     * @return Um array de bytes da mensagem criptografada.
     * @throws Exception Se ocorrer um erro durante a criptografia.
     */
    public static byte[] encrypt(String message, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message.getBytes("UTF-8"));
    }

    /**
     * Descriptografa uma mensagem usando a chave privada do destinatário.
     *
     * @param encrypted O array de bytes da mensagem criptografada.
     * @param key A chave privada do destinatário.
     * @return A mensagem em texto simples.
     * @throws Exception Se ocorrer um erro durante a descriptografia.
     */
    public static String decrypt(byte[] encrypted, PrivateKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, "UTF-8");
    }

    /**
     * Assina uma mensagem com a chave privada do remetente.
     *
     * @param message A mensagem a ser assinada.
     * @param key A chave privada do remetente.
     * @return Um array de bytes da assinatura.
     * @throws Exception Se ocorrer um erro durante a assinatura.
     */
    public static byte[] sign(String message, PrivateKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(message.getBytes("UTF-8"));
        return signature.sign();
    }

    /**
     * Verifica uma assinatura digital com a chave pública do remetente.
     *
     * @param message A mensagem original em texto simples.
     * @param sig O array de bytes da assinatura.
     * @param key A chave pública do remetente.
     * @return True se a assinatura for válida, false caso contrário.
     * @throws Exception Se ocorrer um erro durante a verificação.
     */
    public static boolean verify(String message, byte[] sig, PublicKey key) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(message.getBytes("UTF-8"));
        return signature.verify(sig);
    }
}