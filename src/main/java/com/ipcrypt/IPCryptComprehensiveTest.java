package com.ipcrypt;

import java.net.InetAddress;

/**
 * Comprehensive test class to verify all IPCrypt implementations against the test vectors.
 */
public class IPCryptComprehensiveTest {
    
    public static void main(String[] args) {
        try {
            System.out.println("Testing IPCrypt implementations against all test vectors...");
            
            // Test all vectors
            testAllVectors();
            
            System.out.println("All tests passed!");
        } catch (Exception e) {
            System.err.println("Test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void testAllVectors() throws Exception {
        // Test vector 1: ipcrypt-deterministic
        byte[] key1 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba9876543210");
        InetAddress ip1 = InetAddress.getByName("0.0.0.0");
        InetAddress encrypted1 = IPCryptDeterministic.encrypt(ip1, key1);
        String expected1 = "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb";
        assert encrypted1.getHostAddress().equals(expected1) : 
            "ipcrypt-deterministic test 1 failed: expected " + expected1 + ", got " + encrypted1.getHostAddress();
        System.out.println("ipcrypt-deterministic test 1 passed");
        
        // Test vector 2: ipcrypt-nd
        byte[] key2 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba9876543210");
        InetAddress ip2 = InetAddress.getByName("0.0.0.0");
        byte[] tweak2 = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
        byte[] encrypted2 = IPCryptND.encrypt(ip2, key2, tweak2);
        String expected2 = "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16";
        String actual2 = IPCryptUtils.bytesToHex(encrypted2);
        assert actual2.equals(expected2) : 
            "ipcrypt-nd test 1 failed: expected " + expected2 + ", got " + actual2;
        System.out.println("ipcrypt-nd test 1 passed");
        
        // Test vector 3: ipcrypt-ndx
        byte[] key3 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301");
        InetAddress ip3 = InetAddress.getByName("0.0.0.0");
        byte[] tweak3 = IPCryptUtils.hexToBytes("21bd1834bc088cd2b4ecbe30b70898d7");
        byte[] plaintext3 = IPCryptUtils.ipToBytes(ip3);
        byte[] encrypted3 = IPCryptNDX.aesXTSEncrypt(key3, tweak3, plaintext3);
        byte[] output3 = new byte[32];
        System.arraycopy(tweak3, 0, output3, 0, 16);
        System.arraycopy(encrypted3, 0, output3, 16, 16);
        String expected3 = "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5";
        String actual3 = IPCryptUtils.bytesToHex(output3);
        assert actual3.equals(expected3) : 
            "ipcrypt-ndx test 1 failed: expected " + expected3 + ", got " + actual3;
        System.out.println("ipcrypt-ndx test 1 passed");
        
        // Test vector 4: ipcrypt-deterministic
        byte[] key4 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab8967452301");
        InetAddress ip4 = InetAddress.getByName("255.255.255.255");
        InetAddress encrypted4 = IPCryptDeterministic.encrypt(ip4, key4);
        String expected4 = "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8";
        assert encrypted4.getHostAddress().equals(expected4) : 
            "ipcrypt-deterministic test 2 failed: expected " + expected4 + ", got " + encrypted4.getHostAddress();
        System.out.println("ipcrypt-deterministic test 2 passed");
        
        // Test vector 5: ipcrypt-nd
        byte[] key5 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab8967452301");
        InetAddress ip5 = InetAddress.getByName("255.255.255.255");
        byte[] tweak5 = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
        byte[] encrypted5 = IPCryptND.encrypt(ip5, key5, tweak5);
        String expected5 = "08e0c289bff23b7cf602ae8dcfeb47c1fbcb9597b8951b89";
        String actual5 = IPCryptUtils.bytesToHex(encrypted5);
        assert actual5.equals(expected5) : 
            "ipcrypt-nd test 2 failed: expected " + expected5 + ", got " + actual5;
        System.out.println("ipcrypt-nd test 2 passed");
        
        // Test vector 6: ipcrypt-ndx
        byte[] key6 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210");
        InetAddress ip6 = InetAddress.getByName("255.255.255.255");
        byte[] tweak6 = IPCryptUtils.hexToBytes("21bd1834bc088cd2b4ecbe30b70898d7");
        byte[] plaintext6 = IPCryptUtils.ipToBytes(ip6);
        byte[] encrypted6 = IPCryptNDX.aesXTSEncrypt(key6, tweak6, plaintext6);
        byte[] output6 = new byte[32];
        System.arraycopy(tweak6, 0, output6, 0, 16);
        System.arraycopy(encrypted6, 0, output6, 16, 16);
        String expected6 = "21bd1834bc088cd2b4ecbe30b70898d776c7dbd1ae4802a2dd95ad4f88273535";
        String actual6 = IPCryptUtils.bytesToHex(output6);
        assert actual6.equals(expected6) : 
            "ipcrypt-ndx test 2 failed: expected " + expected6 + ", got " + actual6;
        System.out.println("ipcrypt-ndx test 2 passed");
        
        // Test vector 7: ipcrypt-deterministic
        byte[] key7 = IPCryptUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        InetAddress ip7 = InetAddress.getByName("192.0.2.1");
        InetAddress encrypted7 = IPCryptDeterministic.encrypt(ip7, key7);
        String expected7 = "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777";
        assert encrypted7.getHostAddress().equals(expected7) : 
            "ipcrypt-deterministic test 3 failed: expected " + expected7 + ", got " + encrypted7.getHostAddress();
        System.out.println("ipcrypt-deterministic test 3 passed");
        
        // Test vector 8: ipcrypt-nd
        byte[] key8 = IPCryptUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
        InetAddress ip8 = InetAddress.getByName("192.0.2.1");
        byte[] tweak8 = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
        byte[] encrypted8 = IPCryptND.encrypt(ip8, key8, tweak8);
        String expected8 = "08e0c289bff23b7cca25fe3b7f2ca5e50a0deb24ef0469f8";
        String actual8 = IPCryptUtils.bytesToHex(encrypted8);
        assert actual8.equals(expected8) : 
            "ipcrypt-nd test 3 failed: expected " + expected8 + ", got " + actual8;
        System.out.println("ipcrypt-nd test 3 passed");
        
        // Test vector 9: ipcrypt-ndx
        byte[] key9 = IPCryptUtils.hexToBytes("2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b");
        InetAddress ip9 = InetAddress.getByName("192.0.2.1");
        byte[] tweak9 = IPCryptUtils.hexToBytes("21bd1834bc088cd2b4ecbe30b70898d7");
        byte[] plaintext9 = IPCryptUtils.ipToBytes(ip9);
        byte[] encrypted9 = IPCryptNDX.aesXTSEncrypt(key9, tweak9, plaintext9);
        byte[] output9 = new byte[32];
        System.arraycopy(tweak9, 0, output9, 0, 16);
        System.arraycopy(encrypted9, 0, output9, 16, 16);
        String expected9 = "21bd1834bc088cd2b4ecbe30b70898d7259e85ebaa000667d2437ac7e2208d71";
        String actual9 = IPCryptUtils.bytesToHex(output9);
        assert actual9.equals(expected9) : 
            "ipcrypt-ndx test 3 failed: expected " + expected9 + ", got " + actual9;
        System.out.println("ipcrypt-ndx test 3 passed");
        
        // Test vector 10: ipcrypt-deterministic
        byte[] key10 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba9876543210");
        InetAddress ip10 = InetAddress.getByName("2001:db8:85a3::8a2e:370:7334");
        InetAddress encrypted10 = IPCryptDeterministic.encrypt(ip10, key10);
        String expected10 = "1eef:2352:64c8:18e6:6456:1373:f615:5032";
        assert encrypted10.getHostAddress().equals(expected10) : 
            "ipcrypt-deterministic test 4 failed: expected " + expected10 + ", got " + encrypted10.getHostAddress();
        System.out.println("ipcrypt-deterministic test 4 passed");
        
        // Test vector 11: ipcrypt-nd
        byte[] key11 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba9876543210");
        InetAddress ip11 = InetAddress.getByName("2001:db8:85a3::8a2e:370:7334");
        byte[] tweak11 = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
        byte[] encrypted11 = IPCryptND.encrypt(ip11, key11, tweak11);
        String expected11 = "08e0c289bff23b7cdd344485c55026d8b4cfa33b81032aff";
        String actual11 = IPCryptUtils.bytesToHex(encrypted11);
        assert actual11.equals(expected11) : 
            "ipcrypt-nd test 4 failed: expected " + expected11 + ", got " + actual11;
        System.out.println("ipcrypt-nd test 4 passed");
        
        // Test vector 12: ipcrypt-ndx
        byte[] key12 = IPCryptUtils.hexToBytes("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301");
        InetAddress ip12 = InetAddress.getByName("2001:db8:85a3::8a2e:370:7334");
        byte[] tweak12 = IPCryptUtils.hexToBytes("21bd1834bc088cd2b4ecbe30b70898d7");
        byte[] plaintext12 = IPCryptUtils.ipToBytes(ip12);
        byte[] encrypted12 = IPCryptNDX.aesXTSEncrypt(key12, tweak12, plaintext12);
        byte[] output12 = new byte[32];
        System.arraycopy(tweak12, 0, output12, 0, 16);
        System.arraycopy(encrypted12, 0, output12, 16, 16);
        String expected12 = "21bd1834bc088cd2b4ecbe30b70898d7fe8d52464555ef3458e4a6eefe14eb28";
        String actual12 = IPCryptUtils.bytesToHex(output12);
        assert actual12.equals(expected12) : 
            "ipcrypt-ndx test 4 failed: expected " + expected12 + ", got " + actual12;
        System.out.println("ipcrypt-ndx test 4 passed");
        
        // Test vector 13: ipcrypt-deterministic
        byte[] key13 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab8967452301");
        InetAddress ip13 = InetAddress.getByName("192.0.2.1");
        InetAddress encrypted13 = IPCryptDeterministic.encrypt(ip13, key13);
        String expected13 = "7fde:a680:9546:ef2:d3c:7abb:1b38:2659";
        assert encrypted13.getHostAddress().equals(expected13) : 
            "ipcrypt-deterministic test 5 failed: expected " + expected13 + ", got " + encrypted13.getHostAddress();
        System.out.println("ipcrypt-deterministic test 5 passed");
        
        // Test vector 14: ipcrypt-nd
        byte[] key14 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab8967452301");
        InetAddress ip14 = InetAddress.getByName("192.0.2.1");
        byte[] tweak14 = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
        byte[] encrypted14 = IPCryptND.encrypt(ip14, key14, tweak14);
        String expected14 = "08e0c289bff23b7c18e29f7c1fc75164251238ed9f0bd02a";
        String actual14 = IPCryptUtils.bytesToHex(encrypted14);
        assert actual14.equals(expected14) : 
            "ipcrypt-nd test 5 failed: expected " + expected14 + ", got " + actual14;
        System.out.println("ipcrypt-nd test 5 passed");
        
        // Test vector 15: ipcrypt-ndx
        byte[] key15 = IPCryptUtils.hexToBytes("1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210");
        InetAddress ip15 = InetAddress.getByName("192.0.2.1");
        byte[] tweak15 = IPCryptUtils.hexToBytes("21bd1834bc088cd2b4ecbe30b70898d7");
        byte[] plaintext15 = IPCryptUtils.ipToBytes(ip15);
        byte[] encrypted15 = IPCryptNDX.aesXTSEncrypt(key15, tweak15, plaintext15);
        byte[] output15 = new byte[32];
        System.arraycopy(tweak15, 0, output15, 0, 16);
        System.arraycopy(encrypted15, 0, output15, 16, 16);
        String expected15 = "21bd1834bc088cd2b4ecbe30b70898d7c9487dffa9292855845d234bd1d72395";
        String actual15 = IPCryptUtils.bytesToHex(output15);
        assert actual15.equals(expected15) : 
            "ipcrypt-ndx test 5 failed: expected " + expected15 + ", got " + actual15;
        System.out.println("ipcrypt-ndx test 5 passed");
        
        // Test decryption for deterministic mode
        InetAddress decrypted7 = IPCryptDeterministic.decrypt(encrypted7, key7);
        assert decrypted7.getHostAddress().equals(ip7.getHostAddress()) : 
            "Deterministic decryption test failed: expected " + ip7.getHostAddress() + ", got " + decrypted7.getHostAddress();
        System.out.println("Deterministic decryption test passed");
        
        // Test decryption for ND mode
        InetAddress decrypted8 = IPCryptND.decrypt(encrypted8, key8);
        assert decrypted8.getHostAddress().equals(ip8.getHostAddress()) : 
            "ND decryption test failed: expected " + ip8.getHostAddress() + ", got " + decrypted8.getHostAddress();
        System.out.println("ND decryption test passed");
        
        // Test decryption for NDX mode
        InetAddress decrypted9 = IPCryptNDX.decrypt(output9, key9);
        assert decrypted9.getHostAddress().equals(ip9.getHostAddress()) : 
            "NDX decryption test failed: expected " + ip9.getHostAddress() + ", got " + decrypted9.getHostAddress();
        System.out.println("NDX decryption test passed");
    }
}