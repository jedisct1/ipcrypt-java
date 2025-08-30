package com.ipcrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;

/**
 * Implementation of ipcrypt-deterministic using AES-128.
 */
public class IPCryptDeterministic {
    
    /**
     * Encrypt an IP address using AES-128.
     * 
     * @param ip The IP address to encrypt
     * @param key 16-byte encryption key
     * @return Encrypted IP address
     * @throws Exception if encryption fails
     */
    public static InetAddress encrypt(String ip, byte[] key) throws Exception {
        return encrypt(InetAddress.getByName(ip), key);
    }
    
    /**
     * Encrypt an IP address using AES-128.
     * 
     * @param ip The IP address to encrypt
     * @param key 16-byte encryption key
     * @return Encrypted IP address
     * @throws Exception if encryption fails
     */
    public static InetAddress encrypt(InetAddress ip, byte[] key) throws Exception {
        if (key.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes");
        }
        
        byte[] plaintext = IPCryptUtils.ipToBytes(ip);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        return IPCryptUtils.bytesToIp(ciphertext);
    }
    
    /**
     * Decrypt an IP address using AES-128.
     * 
     * @param encryptedIp The encrypted IP address
     * @param key 16-byte decryption key
     * @return Decrypted IP address
     * @throws Exception if decryption fails
     */
    public static InetAddress decrypt(InetAddress encryptedIp, byte[] key) throws Exception {
        if (key.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes");
        }
        
        byte[] ciphertext = IPCryptUtils.ipToBytes(encryptedIp);
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] plaintext = cipher.doFinal(ciphertext);
        
        return IPCryptUtils.bytesToIp(plaintext);
    }
}