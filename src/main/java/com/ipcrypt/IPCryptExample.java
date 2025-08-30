package com.ipcrypt;

import java.net.InetAddress;

/** Example usage of the IPCrypt library. */
public class IPCryptExample {

  public static void main(String[] args) {
    try {
      System.out.println("IPCrypt Java Implementation Example");
      System.out.println("==================================");

      // Example 1: Deterministic encryption
      System.out.println("\n1. Deterministic Encryption (ipcrypt-deterministic):");
      byte[] deterministicKey = IPCryptUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
      InetAddress ip = InetAddress.getByName("192.0.2.1");
      InetAddress encrypted = IPCryptDeterministic.encrypt(ip, deterministicKey);
      InetAddress decrypted = IPCryptDeterministic.decrypt(encrypted, deterministicKey);

      System.out.println("Original IP: " + ip.getHostAddress());
      System.out.println("Encrypted IP: " + encrypted.getHostAddress());
      System.out.println("Decrypted IP: " + decrypted.getHostAddress());

      // Example 2: Non-deterministic encryption with KIASU-BC
      System.out.println("\n2. Non-Deterministic Encryption (ipcrypt-nd):");
      byte[] ndKey = IPCryptUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
      byte[] tweak = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
      byte[] ndEncrypted = IPCryptND.encrypt(ip, ndKey, tweak);
      InetAddress ndDecrypted = IPCryptND.decrypt(ndEncrypted, ndKey);

      System.out.println("Original IP: " + ip.getHostAddress());
      System.out.println("Encrypted data (hex): " + IPCryptUtils.bytesToHex(ndEncrypted));
      System.out.println("Decrypted IP: " + ndDecrypted.getHostAddress());

      // Example 3: Non-deterministic encryption with AES-XTS
      System.out.println("\n3. Non-Deterministic Encryption (ipcrypt-ndx):");
      byte[] ndxKey =
          IPCryptUtils.hexToBytes(
              "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b");
      byte[] ndxEncrypted = IPCryptNDX.encrypt(ip, ndxKey);
      InetAddress ndxDecrypted = IPCryptNDX.decrypt(ndxEncrypted, ndxKey);

      System.out.println("Original IP: " + ip.getHostAddress());
      System.out.println("Encrypted data (hex): " + IPCryptUtils.bytesToHex(ndxEncrypted));
      System.out.println("Decrypted IP: " + ndxDecrypted.getHostAddress());

      System.out.println("\nAll examples completed successfully!");

    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
      e.printStackTrace();
    }
  }
}
