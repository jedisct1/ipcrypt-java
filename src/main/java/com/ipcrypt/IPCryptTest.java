package com.ipcrypt;

import java.net.InetAddress;

/**
 * Test class to verify the IPCrypt implementations against test vectors.
 */
public class IPCryptTest {
    
    public static void main(String[] args) {
        try {
            System.out.println("Testing IPCrypt implementations...");
            
            // Test deterministic mode
            testDeterministic();
            
            // Test ND mode
            testND();
            
            // Test NDX mode
            testNDX();
            
            System.out.println("All tests passed!");
        } catch (Exception e) {
            System.err.println("Test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void testDeterministic() throws Exception {
        System.out.println("\nTesting ipcrypt-deterministic...");
        
        // Test vector 1
        byte[] key1 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba9876543210");
        InetAddress ip1 = InetAddress.getByName("0.0.0.0");
        InetAddress encrypted1 = IPCryptDeterministic.encrypt(ip1, key1);
        String expected1 = "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb";
        assert encrypted1.getHostAddress().equals(expected1) : 
            "Test 1 failed: expected " + expected1 + ", got " + encrypted1.getHostAddress();
        System.out.println("Test 1 passed");
        
        // Test vector 2
        byte[] key2 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab8967452301");
        InetAddress ip2 = InetAddress.getByName("255.255.255.255");
        InetAddress encrypted2 = IPCryptDeterministic.encrypt(ip2, key2);
        String expected2 = "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8";
        assert encrypted2.getHostAddress().equals(expected2) : 
            "Test 2 failed: expected " + expected2 + ", got " + encrypted2.getHostAddress();
        System.out.println("Test 2 passed");
        
        // Test vector 3
        byte[] key3 = IPCryptUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        InetAddress ip3 = InetAddress.getByName("192.0.2.1");
        InetAddress encrypted3 = IPCryptDeterministic.encrypt(ip3, key3);
        String expected3 = "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777";
        assert encrypted3.getHostAddress().equals(expected3) : 
            "Test 3 failed: expected " + expected3 + ", got " + encrypted3.getHostAddress();
        System.out.println("Test 3 passed");
        
        // Test decryption
        InetAddress decrypted3 = IPCryptDeterministic.decrypt(encrypted3, key3);
        assert decrypted3.getHostAddress().equals(ip3.getHostAddress()) : 
            "Decryption test failed: expected " + ip3.getHostAddress() + ", got " + decrypted3.getHostAddress();
        System.out.println("Decryption test passed");
    }
    
    private static void testND() throws Exception {
        System.out.println("\nTesting ipcrypt-nd...");
        
        // Test vector 1
        byte[] key1 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba9876543210");
        InetAddress ip1 = InetAddress.getByName("0.0.0.0");
        byte[] tweak1 = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
        byte[] encrypted1 = IPCryptND.encrypt(ip1, key1, tweak1);
        String expected1 = "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16";
        String actual1 = IPCryptUtils.bytesToHex(encrypted1);
        assert actual1.equals(expected1) : 
            "Test 1 failed: expected " + expected1 + ", got " + actual1;
        System.out.println("Test 1 passed");
        
        // Test vector 2
        byte[] key2 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab8967452301");
        InetAddress ip2 = InetAddress.getByName("255.255.255.255");
        byte[] tweak2 = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
        byte[] encrypted2 = IPCryptND.encrypt(ip2, key2, tweak2);
        String expected2 = "08e0c289bff23b7cf602ae8dcfeb47c1fbcb9597b8951b89";
        String actual2 = IPCryptUtils.bytesToHex(encrypted2);
        assert actual2.equals(expected2) : 
            "Test 2 failed: expected " + expected2 + ", got " + actual2;
        System.out.println("Test 2 passed");
        
        // Test vector 3
        byte[] key3 = IPCryptUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        InetAddress ip3 = InetAddress.getByName("192.0.2.1");
        byte[] tweak3 = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
        byte[] encrypted3 = IPCryptND.encrypt(ip3, key3, tweak3);
        String expected3 = "08e0c289bff23b7cca25fe3b7f2ca5e50a0deb24ef0469f8";
        String actual3 = IPCryptUtils.bytesToHex(encrypted3);
        assert actual3.equals(expected3) : 
            "Test 3 failed: expected " + expected3 + ", got " + actual3;
        System.out.println("Test 3 passed");
        
        // Test decryption
        InetAddress decrypted3 = IPCryptND.decrypt(encrypted3, key3);
        assert decrypted3.getHostAddress().equals(ip3.getHostAddress()) : 
            "Decryption test failed: expected " + ip3.getHostAddress() + ", got " + decrypted3.getHostAddress();
        System.out.println("Decryption test passed");
    }
    
    private static void testNDX() throws Exception {
        System.out.println("\nTesting ipcrypt-ndx...");
        
        // Test vector 1
        byte[] key1 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301");
        InetAddress ip1 = InetAddress.getByName("0.0.0.0");
        byte[] tweak1 = IPCryptUtils.hexToBytes("21bd1834bc088cd2b4ecbe30b70898d7");
        byte[] plaintext1 = IPCryptUtils.ipToBytes(ip1);
        byte[] encrypted1 = IPCryptNDX.aesXTSEncrypt(key1, tweak1, plaintext1);
        String expectedCiphertext1 = "82db0d4125fdace61db35b8339f20ee5";
        String actualCiphertext1 = IPCryptUtils.bytesToHex(encrypted1);
        assert actualCiphertext1.equals(expectedCiphertext1) : 
            "Ciphertext test 1 failed: expected " + expectedCiphertext1 + ", got " + actualCiphertext1;
        
        byte[] output1 = new byte[32];
        System.arraycopy(tweak1, 0, output1, 0, 16);
        System.arraycopy(encrypted1, 0, output1, 16, 16);
        String expected1 = "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5";
        String actual1 = IPCryptUtils.bytesToHex(output1);
        assert actual1.equals(expected1) : 
            "Test 1 failed: expected " + expected1 + ", got " + actual1;
        System.out.println("Test 1 passed");
        
        // Test vector 2
        byte[] key2 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210");
        InetAddress ip2 = InetAddress.getByName("255.255.255.255");
        byte[] tweak2 = IPCryptUtils.hexToBytes("21bd1834bc088cd2b4ecbe30b70898d7");
        byte[] plaintext2 = IPCryptUtils.ipToBytes(ip2);
        byte[] encrypted2 = IPCryptNDX.aesXTSEncrypt(key2, tweak2, plaintext2);
        String expectedCiphertext2 = "76c7dbd1ae4802a2dd95ad4f88273535";
        String actualCiphertext2 = IPCryptUtils.bytesToHex(encrypted2);
        assert actualCiphertext2.equals(expectedCiphertext2) : 
            "Ciphertext test 2 failed: expected " + expectedCiphertext2 + ", got " + actualCiphertext2;
        
        byte[] output2 = new byte[32];
        System.arraycopy(tweak2, 0, output2, 0, 16);
        System.arraycopy(encrypted2, 0, output2, 16, 16);
        String expected2 = "21bd1834bc088cd2b4ecbe30b70898d776c7dbd1ae4802a2dd95ad4f88273535";
        String actual2 = IPCryptUtils.bytesToHex(output2);
        assert actual2.equals(expected2) : 
            "Test 2 failed: expected " + expected2 + ", got " + actual2;
        System.out.println("Test 2 passed");
        
        // Test vector 3
        byte[] key3 = IPCryptUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b");
        InetAddress ip3 = InetAddress.getByName("192.0.2.1");
        byte[] tweak3 = IPCryptUtils.hexToBytes("21bd1834bc088cd2b4ecbe30b70898d7");
        byte[] plaintext3 = IPCryptUtils.ipToBytes(ip3);
        byte[] encrypted3 = IPCryptNDX.aesXTSEncrypt(key3, tweak3, plaintext3);
        String expectedCiphertext3 = "259e85ebaa000667d2437ac7e2208d71";
        String actualCiphertext3 = IPCryptUtils.bytesToHex(encrypted3);
        assert actualCiphertext3.equals(expectedCiphertext3) : 
            "Ciphertext test 3 failed: expected " + expectedCiphertext3 + ", got " + actualCiphertext3;
        
        byte[] output3 = new byte[32];
        System.arraycopy(tweak3, 0, output3, 0, 16);
        System.arraycopy(encrypted3, 0, output3, 16, 16);
        String expected3 = "21bd1834bc088cd2b4ecbe30b70898d7259e85ebaa000667d2437ac7e2208d71";
        String actual3 = IPCryptUtils.bytesToHex(output3);
        assert actual3.equals(expected3) : 
            "Test 3 failed: expected " + expected3 + ", got " + actual3;
        System.out.println("Test 3 passed");
        
        // Test decryption
        byte[] fullOutput3 = new byte[32];
        System.arraycopy(tweak3, 0, fullOutput3, 0, 16);
        System.arraycopy(encrypted3, 0, fullOutput3, 16, 16);
        InetAddress decrypted3 = IPCryptNDX.decrypt(fullOutput3, key3);
        assert decrypted3.getHostAddress().equals(ip3.getHostAddress()) : 
            "Decryption test failed: expected " + ip3.getHostAddress() + ", got " + decrypted3.getHostAddress();
        System.out.println("Decryption test passed");
    }
}