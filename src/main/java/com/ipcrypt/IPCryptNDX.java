package com.ipcrypt;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Implementation of ipcrypt-ndx using AES-XTS with a 16-byte tweak.
 */
public class IPCryptNDX {
    
    /**
     * Encrypt using AES-XTS construction.
     * 
     * @param key 32-byte key (two 16-byte AES keys)
     * @param tweak 16-byte tweak
     * @param plaintext 16-byte plaintext
     * @return 16-byte ciphertext
     * @throws Exception if encryption fails
     */
    public static byte[] aesXTSEncrypt(byte[] key, byte[] tweak, byte[] plaintext) throws Exception {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        if (tweak.length != 16) {
            throw new IllegalArgumentException("Tweak must be 16 bytes");
        }
        if (plaintext.length != 16) {
            throw new IllegalArgumentException("Plaintext must be 16 bytes");
        }
        
        // Split key into two 16-byte keys
        byte[] k1 = Arrays.copyOfRange(key, 0, 16);
        byte[] k2 = Arrays.copyOfRange(key, 16, 32);
        
        // Encrypt tweak with second key
        SecretKeySpec secretKey2 = new SecretKeySpec(k2, "AES");
        Cipher cipher2 = Cipher.getInstance("AES/ECB/NoPadding");
        cipher2.init(Cipher.ENCRYPT_MODE, secretKey2);
        byte[] et = cipher2.doFinal(tweak);
        
        // XOR plaintext with encrypted tweak
        byte[] xored = new byte[16];
        for (int i = 0; i < 16; i++) {
            xored[i] = (byte) (plaintext[i] ^ et[i]);
        }
        
        // Encrypt with first key
        SecretKeySpec secretKey1 = new SecretKeySpec(k1, "AES");
        Cipher cipher1 = Cipher.getInstance("AES/ECB/NoPadding");
        cipher1.init(Cipher.ENCRYPT_MODE, secretKey1);
        byte[] encrypted = cipher1.doFinal(xored);
        
        // XOR result with encrypted tweak
        byte[] result = new byte[16];
        for (int i = 0; i < 16; i++) {
            result[i] = (byte) (encrypted[i] ^ et[i]);
        }
        
        return result;
    }
    
    /**
     * Decrypt using AES-XTS construction.
     * 
     * @param key 32-byte key (two 16-byte AES keys)
     * @param tweak 16-byte tweak
     * @param ciphertext 16-byte ciphertext
     * @return 16-byte plaintext
     * @throws Exception if decryption fails
     */
    public static byte[] aesXTSDecrypt(byte[] key, byte[] tweak, byte[] ciphertext) throws Exception {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        if (tweak.length != 16) {
            throw new IllegalArgumentException("Tweak must be 16 bytes");
        }
        if (ciphertext.length != 16) {
            throw new IllegalArgumentException("Ciphertext must be 16 bytes");
        }
        
        // Split key into two 16-byte keys
        byte[] k1 = Arrays.copyOfRange(key, 0, 16);
        byte[] k2 = Arrays.copyOfRange(key, 16, 32);
        
        // Encrypt tweak with second key
        SecretKeySpec secretKey2 = new SecretKeySpec(k2, "AES");
        Cipher cipher2 = Cipher.getInstance("AES/ECB/NoPadding");
        cipher2.init(Cipher.ENCRYPT_MODE, secretKey2);
        byte[] et = cipher2.doFinal(tweak);
        
        // XOR ciphertext with encrypted tweak
        byte[] xored = new byte[16];
        for (int i = 0; i < 16; i++) {
            xored[i] = (byte) (ciphertext[i] ^ et[i]);
        }
        
        // Decrypt with first key
        SecretKeySpec secretKey1 = new SecretKeySpec(k1, "AES");
        Cipher cipher1 = Cipher.getInstance("AES/ECB/NoPadding");
        cipher1.init(Cipher.DECRYPT_MODE, secretKey1);
        byte[] decrypted = cipher1.doFinal(xored);
        
        // XOR result with encrypted tweak
        byte[] result = new byte[16];
        for (int i = 0; i < 16; i++) {
            result[i] = (byte) (decrypted[i] ^ et[i]);
        }
        
        return result;
    }
    
    /**
     * Encrypt an IP address using AES-XTS.
     * 
     * @param ip IP address to encrypt
     * @param key 32-byte encryption key
     * @return 32-byte output (tweak || ciphertext)
     * @throws Exception if encryption fails
     */
    public static byte[] encrypt(String ip, byte[] key) throws Exception {
        return encrypt(InetAddress.getByName(ip), key);
    }
    
    /**
     * Encrypt an IP address using AES-XTS.
     * 
     * @param ip IP address to encrypt
     * @param key 32-byte encryption key
     * @return 32-byte output (tweak || ciphertext)
     * @throws Exception if encryption fails
     */
    public static byte[] encrypt(InetAddress ip, byte[] key) throws Exception {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        
        // Generate random 16-byte tweak
        byte[] tweak = new byte[16];
        new SecureRandom().nextBytes(tweak);
        
        // Convert IP to bytes and encrypt
        byte[] plaintext = IPCryptUtils.ipToBytes(ip);
        byte[] ciphertext = aesXTSEncrypt(key, tweak, plaintext);
        
        // Return tweak || ciphertext
        byte[] result = new byte[32];
        System.arraycopy(tweak, 0, result, 0, 16);
        System.arraycopy(ciphertext, 0, result, 16, 16);
        return result;
    }
    
    /**
     * Decrypt a binary output using AES-XTS.
     * 
     * @param binaryOutput 32-byte encrypted data (tweak || ciphertext)
     * @param key 32-byte decryption key
     * @return Decrypted IP address
     * @throws Exception if decryption fails
     */
    public static InetAddress decrypt(byte[] binaryOutput, byte[] key) throws Exception {
        if (key.length != 32) {
            throw new IllegalArgumentException("Key must be 32 bytes");
        }
        if (binaryOutput.length != 32) {
            throw new IllegalArgumentException("Binary output must be 32 bytes");
        }
        
        // Split into tweak and ciphertext
        byte[] tweak = Arrays.copyOfRange(binaryOutput, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(binaryOutput, 16, 32);
        
        // Decrypt and convert back to IP
        byte[] plaintext = aesXTSDecrypt(key, tweak, ciphertext);
        return IPCryptUtils.bytesToIp(plaintext);
    }
}