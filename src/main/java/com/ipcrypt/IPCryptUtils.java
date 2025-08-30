package com.ipcrypt;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * Utility class for common IPCrypt operations.
 */
public class IPCryptUtils {
    
    /**
     * Convert an IP address to its 16-byte representation.
     * 
     * @param ip IP address as string
     * @return 16-byte representation
     * @throws UnknownHostException if IP address is invalid
     */
    public static byte[] ipToBytes(String ip) throws UnknownHostException {
        return ipToBytes(InetAddress.getByName(ip));
    }
    
    /**
     * Convert an IP address to its 16-byte representation.
     * 
     * @param ip IP address as InetAddress
     * @return 16-byte representation
     */
    public static byte[] ipToBytes(InetAddress ip) {
        if (ip instanceof Inet4Address) {
            // Convert IPv4 to IPv4-mapped IPv6 format (::ffff:0:0/96)
            byte[] ipv4Bytes = ip.getAddress();
            byte[] result = new byte[16];
            // First 10 bytes are 0
            // Bytes 11 and 12 are 0xFF
            result[10] = (byte) 0xFF;
            result[11] = (byte) 0xFF;
            // Last 4 bytes are the IPv4 address
            System.arraycopy(ipv4Bytes, 0, result, 12, 4);
            return result;
        } else {
            return ip.getAddress();
        }
    }
    
    /**
     * Convert a 16-byte representation back to an IP address.
     * 
     * @param bytes16 16-byte representation
     * @return IP address as InetAddress
     * @throws UnknownHostException if byte array is invalid
     */
    public static InetAddress bytesToIp(byte[] bytes16) throws UnknownHostException {
        if (bytes16.length != 16) {
            throw new IllegalArgumentException("Input must be 16 bytes");
        }
        
        // Check for IPv4-mapped IPv6 format
        if (isIPv4Mapped(bytes16)) {
            // Extract the IPv4 part (last 4 bytes)
            byte[] ipv4Bytes = Arrays.copyOfRange(bytes16, 12, 16);
            return InetAddress.getByAddress(ipv4Bytes);
        } else {
            return InetAddress.getByAddress(bytes16);
        }
    }
    
    /**
     * Check if the 16-byte array represents an IPv4-mapped IPv6 address.
     * 
     * @param bytes16 16-byte array
     * @return true if it's an IPv4-mapped IPv6 address, false otherwise
     */
    private static boolean isIPv4Mapped(byte[] bytes16) {
        // First 10 bytes should be 0, bytes 11 and 12 should be 0xFF
        for (int i = 0; i < 10; i++) {
            if (bytes16[i] != 0) {
                return false;
            }
        }
        return bytes16[10] == (byte) 0xFF && bytes16[11] == (byte) 0xFF;
    }
    
    /**
     * Convert a hex string to byte array.
     * 
     * @param hex Hex string
     * @return Byte array
     */
    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
    
    /**
     * Convert byte array to hex string.
     * 
     * @param bytes Byte array
     * @return Hex string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}