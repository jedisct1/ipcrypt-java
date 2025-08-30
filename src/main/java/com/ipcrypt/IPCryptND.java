package com.ipcrypt;

import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Arrays;

/** Implementation of ipcrypt-nd using KIASU-BC. */
public class IPCryptND {

  // AES S-box
  private static final byte[] SBOX = {
    (byte) 0x63, (byte) 0x7c, (byte) 0x77, (byte) 0x7b, (byte) 0xf2, (byte) 0x6b, (byte) 0x6f,
        (byte) 0xc5,
    (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab,
        (byte) 0x76,
    (byte) 0xca, (byte) 0x82, (byte) 0xc9, (byte) 0x7d, (byte) 0xfa, (byte) 0x59, (byte) 0x47,
        (byte) 0xf0,
    (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, (byte) 0x72,
        (byte) 0xc0,
    (byte) 0xb7, (byte) 0xfd, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3f, (byte) 0xf7,
        (byte) 0xcc,
    (byte) 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, (byte) 0x71, (byte) 0xd8, (byte) 0x31,
        (byte) 0x15,
    (byte) 0x04, (byte) 0xc7, (byte) 0x23, (byte) 0xc3, (byte) 0x18, (byte) 0x96, (byte) 0x05,
        (byte) 0x9a,
    (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, (byte) 0x27, (byte) 0xb2,
        (byte) 0x75,
    (byte) 0x09, (byte) 0x83, (byte) 0x2c, (byte) 0x1a, (byte) 0x1b, (byte) 0x6e, (byte) 0x5a,
        (byte) 0xa0,
    (byte) 0x52, (byte) 0x3b, (byte) 0xd6, (byte) 0xb3, (byte) 0x29, (byte) 0xe3, (byte) 0x2f,
        (byte) 0x84,
    (byte) 0x53, (byte) 0xd1, (byte) 0x00, (byte) 0xed, (byte) 0x20, (byte) 0xfc, (byte) 0xb1,
        (byte) 0x5b,
    (byte) 0x6a, (byte) 0xcb, (byte) 0xbe, (byte) 0x39, (byte) 0x4a, (byte) 0x4c, (byte) 0x58,
        (byte) 0xcf,
    (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, (byte) 0x43, (byte) 0x4d, (byte) 0x33,
        (byte) 0x85,
    (byte) 0x45, (byte) 0xf9, (byte) 0x02, (byte) 0x7f, (byte) 0x50, (byte) 0x3c, (byte) 0x9f,
        (byte) 0xa8,
    (byte) 0x51, (byte) 0xa3, (byte) 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, (byte) 0x38,
        (byte) 0xf5,
    (byte) 0xbc, (byte) 0xb6, (byte) 0xda, (byte) 0x21, (byte) 0x10, (byte) 0xff, (byte) 0xf3,
        (byte) 0xd2,
    (byte) 0xcd, (byte) 0x0c, (byte) 0x13, (byte) 0xec, (byte) 0x5f, (byte) 0x97, (byte) 0x44,
        (byte) 0x17,
    (byte) 0xc4, (byte) 0xa7, (byte) 0x7e, (byte) 0x3d, (byte) 0x64, (byte) 0x5d, (byte) 0x19,
        (byte) 0x73,
    (byte) 0x60, (byte) 0x81, (byte) 0x4f, (byte) 0xdc, (byte) 0x22, (byte) 0x2a, (byte) 0x90,
        (byte) 0x88,
    (byte) 0x46, (byte) 0xee, (byte) 0xb8, (byte) 0x14, (byte) 0xde, (byte) 0x5e, (byte) 0x0b,
        (byte) 0xdb,
    (byte) 0xe0, (byte) 0x32, (byte) 0x3a, (byte) 0x0a, (byte) 0x49, (byte) 0x06, (byte) 0x24,
        (byte) 0x5c,
    (byte) 0xc2, (byte) 0xd3, (byte) 0xac, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4,
        (byte) 0x79,
    (byte) 0xe7, (byte) 0xc8, (byte) 0x37, (byte) 0x6d, (byte) 0x8d, (byte) 0xd5, (byte) 0x4e,
        (byte) 0xa9,
    (byte) 0x6c, (byte) 0x56, (byte) 0xf4, (byte) 0xea, (byte) 0x65, (byte) 0x7a, (byte) 0xae,
        (byte) 0x08,
    (byte) 0xba, (byte) 0x78, (byte) 0x25, (byte) 0x2e, (byte) 0x1c, (byte) 0xa6, (byte) 0xb4,
        (byte) 0xc6,
    (byte) 0xe8, (byte) 0xdd, (byte) 0x74, (byte) 0x1f, (byte) 0x4b, (byte) 0xbd, (byte) 0x8b,
        (byte) 0x8a,
    (byte) 0x70, (byte) 0x3e, (byte) 0xb5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xf6,
        (byte) 0x0e,
    (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, (byte) 0x1d,
        (byte) 0x9e,
    (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e,
        (byte) 0x94,
    (byte) 0x9b, (byte) 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, (byte) 0x55, (byte) 0x28,
        (byte) 0xdf,
    (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42,
        (byte) 0x68,
    (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb,
        (byte) 0x16
  };

  // AES inverse S-box
  private static final byte[] INV_SBOX = {
    (byte) 0x52, (byte) 0x09, (byte) 0x6a, (byte) 0xd5, (byte) 0x30, (byte) 0x36, (byte) 0xa5,
        (byte) 0x38,
    (byte) 0xbf, (byte) 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7,
        (byte) 0xfb,
    (byte) 0x7c, (byte) 0xe3, (byte) 0x39, (byte) 0x82, (byte) 0x9b, (byte) 0x2f, (byte) 0xff,
        (byte) 0x87,
    (byte) 0x34, (byte) 0x8e, (byte) 0x43, (byte) 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9,
        (byte) 0xcb,
    (byte) 0x54, (byte) 0x7b, (byte) 0x94, (byte) 0x32, (byte) 0xa6, (byte) 0xc2, (byte) 0x23,
        (byte) 0x3d,
    (byte) 0xee, (byte) 0x4c, (byte) 0x95, (byte) 0x0b, (byte) 0x42, (byte) 0xfa, (byte) 0xc3,
        (byte) 0x4e,
    (byte) 0x08, (byte) 0x2e, (byte) 0xa1, (byte) 0x66, (byte) 0x28, (byte) 0xd9, (byte) 0x24,
        (byte) 0xb2,
    (byte) 0x76, (byte) 0x5b, (byte) 0xa2, (byte) 0x49, (byte) 0x6d, (byte) 0x8b, (byte) 0xd1,
        (byte) 0x25,
    (byte) 0x72, (byte) 0xf8, (byte) 0xf6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98,
        (byte) 0x16,
    (byte) 0xd4, (byte) 0xa4, (byte) 0x5c, (byte) 0xcc, (byte) 0x5d, (byte) 0x65, (byte) 0xb6,
        (byte) 0x92,
    (byte) 0x6c, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9,
        (byte) 0xda,
    (byte) 0x5e, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d,
        (byte) 0x84,
    (byte) 0x90, (byte) 0xd8, (byte) 0xab, (byte) 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3,
        (byte) 0x0a,
    (byte) 0xf7, (byte) 0xe4, (byte) 0x58, (byte) 0x05, (byte) 0xb8, (byte) 0xb3, (byte) 0x45,
        (byte) 0x06,
    (byte) 0xd0, (byte) 0x2c, (byte) 0x1e, (byte) 0x8f, (byte) 0xca, (byte) 0x3f, (byte) 0x0f,
        (byte) 0x02,
    (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8a,
        (byte) 0x6b,
    (byte) 0x3a, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4f, (byte) 0x67, (byte) 0xdc,
        (byte) 0xea,
    (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6,
        (byte) 0x73,
    (byte) 0x96, (byte) 0xac, (byte) 0x74, (byte) 0x22, (byte) 0xe7, (byte) 0xad, (byte) 0x35,
        (byte) 0x85,
    (byte) 0xe2, (byte) 0xf9, (byte) 0x37, (byte) 0xe8, (byte) 0x1c, (byte) 0x75, (byte) 0xdf,
        (byte) 0x6e,
    (byte) 0x47, (byte) 0xf1, (byte) 0x1a, (byte) 0x71, (byte) 0x1d, (byte) 0x29, (byte) 0xc5,
        (byte) 0x89,
    (byte) 0x6f, (byte) 0xb7, (byte) 0x62, (byte) 0x0e, (byte) 0xaa, (byte) 0x18, (byte) 0xbe,
        (byte) 0x1b,
    (byte) 0xfc, (byte) 0x56, (byte) 0x3e, (byte) 0x4b, (byte) 0xc6, (byte) 0xd2, (byte) 0x79,
        (byte) 0x20,
    (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, (byte) 0x78, (byte) 0xcd, (byte) 0x5a,
        (byte) 0xf4,
    (byte) 0x1f, (byte) 0xdd, (byte) 0xa8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xc7,
        (byte) 0x31,
    (byte) 0xb1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xec,
        (byte) 0x5f,
    (byte) 0x60, (byte) 0x51, (byte) 0x7f, (byte) 0xa9, (byte) 0x19, (byte) 0xb5, (byte) 0x4a,
        (byte) 0x0d,
    (byte) 0x2d, (byte) 0xe5, (byte) 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c,
        (byte) 0xef,
    (byte) 0xa0, (byte) 0xe0, (byte) 0x3b, (byte) 0x4d, (byte) 0xae, (byte) 0x2a, (byte) 0xf5,
        (byte) 0xb0,
    (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, (byte) 0x3c, (byte) 0x83, (byte) 0x53, (byte) 0x99,
        (byte) 0x61,
    (byte) 0x17, (byte) 0x2b, (byte) 0x04, (byte) 0x7e, (byte) 0xba, (byte) 0x77, (byte) 0xd6,
        (byte) 0x26,
    (byte) 0xe1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0c,
        (byte) 0x7d
  };

  // AES round constants
  private static final byte[] RCON = {
    (byte) 0x01,
    (byte) 0x02,
    (byte) 0x04,
    (byte) 0x08,
    (byte) 0x10,
    (byte) 0x20,
    (byte) 0x40,
    (byte) 0x80,
    (byte) 0x1b,
    (byte) 0x36
  };

  // Precomputed multiplication tables for AES operations
  private static final byte[] MUL2 = new byte[256];
  private static final byte[] MUL3 = new byte[256];

  static {
    for (int x = 0; x < 256; x++) {
      MUL2[x] = (byte) ((x << 1) & 0xFF ^ (0x1B & -(x >> 7)));
      MUL3[x] = (byte) (MUL2[x] ^ x);
    }
  }

  /**
   * Apply the AES S-box to each byte of the state.
   *
   * @param state Input state
   * @return Output state after SubBytes
   */
  private static byte[] subBytes(byte[] state) {
    byte[] result = new byte[state.length];
    for (int i = 0; i < state.length; i++) {
      result[i] = SBOX[state[i] & 0xFF];
    }
    return result;
  }

  /**
   * Apply the AES inverse S-box to each byte of the state.
   *
   * @param state Input state
   * @return Output state after InvSubBytes
   */
  private static byte[] invSubBytes(byte[] state) {
    byte[] result = new byte[state.length];
    for (int i = 0; i < state.length; i++) {
      result[i] = INV_SBOX[state[i] & 0xFF];
    }
    return result;
  }

  /**
   * XOR two byte arrays.
   *
   * @param a First array
   * @param b Second array
   * @return XOR result
   */
  private static byte[] xorBytes(byte[] a, byte[] b) {
    byte[] result = new byte[a.length];
    for (int i = 0; i < a.length; i++) {
      result[i] = (byte) (a[i] ^ b[i]);
    }
    return result;
  }

  /**
   * Rotate a 4-byte word.
   *
   * @param word 4-byte word
   * @return Rotated word
   */
  private static byte[] rotWord(byte[] word) {
    if (word.length != 4) {
      throw new IllegalArgumentException("Word must be 4 bytes");
    }
    byte[] result = new byte[4];
    result[0] = word[1];
    result[1] = word[2];
    result[2] = word[3];
    result[3] = word[0];
    return result;
  }

  /**
   * Generate AES round keys.
   *
   * @param key 16-byte key
   * @return Array of 11 round keys
   */
  private static byte[][] expandKey(byte[] key) {
    if (key.length != 16) {
      throw new IllegalArgumentException("Key must be 16 bytes");
    }

    byte[][] roundKeys = new byte[11][16];
    System.arraycopy(key, 0, roundKeys[0], 0, 16);

    for (int i = 1; i < 11; i++) {
      byte[] prevKey = roundKeys[i - 1];
      byte[] temp = Arrays.copyOfRange(prevKey, 12, 16);
      temp = rotWord(temp);
      temp = subBytes(temp);

      // XOR with RCON
      temp[0] = (byte) (temp[0] ^ RCON[i - 1]);

      byte[] newKey = new byte[16];
      for (int j = 0; j < 4; j++) {
        byte[] word = Arrays.copyOfRange(prevKey, j * 4, (j + 1) * 4);
        if (j == 0) {
          word = xorBytes(word, temp);
        } else {
          byte[] prevNewWord = Arrays.copyOfRange(newKey, (j - 1) * 4, j * 4);
          word = xorBytes(word, prevNewWord);
        }
        System.arraycopy(word, 0, newKey, j * 4, 4);
      }
      roundKeys[i] = newKey;
    }

    return roundKeys;
  }

  /**
   * Pad an 8-byte tweak to 16 bytes by placing each 2-byte pair at the start of each 4-byte group.
   *
   * @param tweak 8-byte tweak
   * @return 16-byte padded tweak
   */
  private static byte[] padTweak(byte[] tweak) {
    if (tweak.length != 8) {
      throw new IllegalArgumentException("Tweak must be 8 bytes");
    }

    byte[] paddedTweak = new byte[16];
    for (int i = 0; i < 4; i++) {
      paddedTweak[i * 4] = tweak[i * 2];
      paddedTweak[i * 4 + 1] = tweak[i * 2 + 1];
      // paddedTweak[i*4 + 2] and paddedTweak[i*4 + 3] are already 0
    }
    return paddedTweak;
  }

  /**
   * Perform AES ShiftRows operation.
   *
   * @param state Input state
   * @return Output state after ShiftRows
   */
  private static byte[] shiftRows(byte[] state) {
    byte[] result = new byte[16];
    // Row 0: no shift
    result[0] = state[0];
    result[4] = state[4];
    result[8] = state[8];
    result[12] = state[12];
    // Row 1: shift left by 1
    result[1] = state[5];
    result[5] = state[9];
    result[9] = state[13];
    result[13] = state[1];
    // Row 2: shift left by 2
    result[2] = state[10];
    result[6] = state[14];
    result[10] = state[2];
    result[14] = state[6];
    // Row 3: shift left by 3
    result[3] = state[15];
    result[7] = state[3];
    result[11] = state[7];
    result[15] = state[11];
    return result;
  }

  /**
   * Perform inverse AES ShiftRows operation.
   *
   * @param state Input state
   * @return Output state after InvShiftRows
   */
  private static byte[] invShiftRows(byte[] state) {
    byte[] result = new byte[16];
    // Row 0: no shift
    result[0] = state[0];
    result[4] = state[4];
    result[8] = state[8];
    result[12] = state[12];
    // Row 1: shift right by 1
    result[1] = state[13];
    result[5] = state[1];
    result[9] = state[5];
    result[13] = state[9];
    // Row 2: shift right by 2
    result[2] = state[10];
    result[6] = state[14];
    result[10] = state[2];
    result[14] = state[6];
    // Row 3: shift right by 3
    result[3] = state[7];
    result[7] = state[11];
    result[11] = state[15];
    result[15] = state[3];
    return result;
  }

  /**
   * Perform AES MixColumns operation.
   *
   * @param state Input state
   * @return Output state after MixColumns
   */
  private static byte[] mixColumns(byte[] state) {
    byte[] newState = new byte[16];
    for (int c = 0; c < 4; c++) {
      int s0 = state[c * 4] & 0xFF;
      int s1 = state[c * 4 + 1] & 0xFF;
      int s2 = state[c * 4 + 2] & 0xFF;
      int s3 = state[c * 4 + 3] & 0xFF;

      newState[c * 4] = (byte) (MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3);
      newState[c * 4 + 1] = (byte) (s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3);
      newState[c * 4 + 2] = (byte) (s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3]);
      newState[c * 4 + 3] = (byte) (MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3]);
    }
    return newState;
  }

  /**
   * Multiply byte by 0x09 in GF(2^8).
   *
   * @param b Input byte
   * @return Result of multiplication
   */
  private static byte mul09(byte b) {
    return (byte) (MUL2[MUL2[MUL2[b & 0xFF] & 0xFF] & 0xFF] ^ b);
  }

  /**
   * Multiply byte by 0x0B in GF(2^8).
   *
   * @param b Input byte
   * @return Result of multiplication
   */
  private static byte mul0B(byte b) {
    return (byte) (MUL2[MUL2[MUL2[b & 0xFF] & 0xFF] & 0xFF] ^ MUL2[b & 0xFF] ^ b);
  }

  /**
   * Multiply byte by 0x0D in GF(2^8).
   *
   * @param b Input byte
   * @return Result of multiplication
   */
  private static byte mul0D(byte b) {
    int x2 = MUL2[b & 0xFF] & 0xFF;
    int x4 = MUL2[x2] & 0xFF;
    int x8 = MUL2[x4] & 0xFF;
    return (byte) (x8 ^ x4 ^ b);
  }

  /**
   * Multiply byte by 0x0E in GF(2^8).
   *
   * @param b Input byte
   * @return Result of multiplication
   */
  private static byte mul0E(byte b) {
    int x2 = MUL2[b & 0xFF] & 0xFF;
    int x4 = MUL2[x2] & 0xFF;
    int x8 = MUL2[x4] & 0xFF;
    return (byte) (x8 ^ x4 ^ x2);
  }

  /**
   * Perform inverse AES MixColumns operation.
   *
   * @param state Input state
   * @return Output state after InvMixColumns
   */
  private static byte[] invMixColumns(byte[] state) {
    byte[] newState = new byte[16];
    for (int c = 0; c < 4; c++) {
      int s0 = state[c * 4] & 0xFF;
      int s1 = state[c * 4 + 1] & 0xFF;
      int s2 = state[c * 4 + 2] & 0xFF;
      int s3 = state[c * 4 + 3] & 0xFF;

      newState[c * 4] =
          (byte)
              ((mul0E((byte) s0) ^ mul0B((byte) s1) ^ mul0D((byte) s2) ^ mul09((byte) s3)) & 0xFF);
      newState[c * 4 + 1] =
          (byte)
              ((mul09((byte) s0) ^ mul0E((byte) s1) ^ mul0B((byte) s2) ^ mul0D((byte) s3)) & 0xFF);
      newState[c * 4 + 2] =
          (byte)
              ((mul0D((byte) s0) ^ mul09((byte) s1) ^ mul0E((byte) s2) ^ mul0B((byte) s3)) & 0xFF);
      newState[c * 4 + 3] =
          (byte)
              ((mul0B((byte) s0) ^ mul0D((byte) s1) ^ mul09((byte) s2) ^ mul0E((byte) s3)) & 0xFF);
    }
    return newState;
  }

  /**
   * Encrypt using KIASU-BC construction.
   *
   * @param key 16-byte key
   * @param tweak 8-byte tweak
   * @param plaintext 16-byte plaintext
   * @return 16-byte ciphertext
   */
  public static byte[] kiasuBCEncrypt(byte[] key, byte[] tweak, byte[] plaintext) {
    if (key.length != 16) {
      throw new IllegalArgumentException("Key must be 16 bytes");
    }
    if (tweak.length != 8) {
      throw new IllegalArgumentException("Tweak must be 8 bytes");
    }
    if (plaintext.length != 16) {
      throw new IllegalArgumentException("Plaintext must be 16 bytes");
    }

    byte[][] roundKeys = expandKey(key);
    byte[] paddedTweak = padTweak(tweak);

    byte[] state = xorBytes(plaintext, xorBytes(roundKeys[0], paddedTweak));
    for (int i = 1; i < 10; i++) {
      state = subBytes(state);
      state = shiftRows(state);
      state = mixColumns(state);
      state = xorBytes(state, xorBytes(roundKeys[i], paddedTweak));
    }

    state = subBytes(state);
    state = shiftRows(state);
    state = xorBytes(state, xorBytes(roundKeys[10], paddedTweak));

    return state;
  }

  /**
   * Decrypt using KIASU-BC construction.
   *
   * @param key 16-byte key
   * @param tweak 8-byte tweak
   * @param ciphertext 16-byte ciphertext
   * @return 16-byte plaintext
   */
  public static byte[] kiasuBCDecrypt(byte[] key, byte[] tweak, byte[] ciphertext) {
    if (key.length != 16) {
      throw new IllegalArgumentException("Key must be 16 bytes");
    }
    if (tweak.length != 8) {
      throw new IllegalArgumentException("Tweak must be 8 bytes");
    }
    if (ciphertext.length != 16) {
      throw new IllegalArgumentException("Ciphertext must be 16 bytes");
    }

    byte[][] roundKeys = expandKey(key);
    byte[] paddedTweak = padTweak(tweak);

    byte[] state = xorBytes(ciphertext, xorBytes(roundKeys[10], paddedTweak));
    state = invShiftRows(state);
    state = invSubBytes(state);

    for (int i = 9; i >= 1; i--) {
      state = xorBytes(state, xorBytes(roundKeys[i], paddedTweak));
      state = invMixColumns(state);
      state = invShiftRows(state);
      state = invSubBytes(state);
    }

    state = xorBytes(state, xorBytes(roundKeys[0], paddedTweak));

    return state;
  }

  /**
   * Encrypt an IP address using ipcrypt-nd.
   *
   * @param ipAddress IP address to encrypt
   * @param key 16-byte encryption key
   * @param tweak 8-byte tweak (optional, will generate random if null)
   * @return 24-byte output (tweak || ciphertext)
   * @throws Exception if encryption fails
   */
  public static byte[] encrypt(String ipAddress, byte[] key, byte[] tweak) throws Exception {
    return encrypt(InetAddress.getByName(ipAddress), key, tweak);
  }

  /**
   * Encrypt an IP address using ipcrypt-nd.
   *
   * @param ipAddress IP address to encrypt
   * @param key 16-byte encryption key
   * @param tweak 8-byte tweak (optional, will generate random if null)
   * @return 24-byte output (tweak || ciphertext)
   * @throws Exception if encryption fails
   */
  public static byte[] encrypt(InetAddress ipAddress, byte[] key, byte[] tweak) throws Exception {
    // Convert IP to bytes
    byte[] ipBytes = IPCryptUtils.ipToBytes(ipAddress);

    // Use provided tweak or generate random 8-byte tweak
    if (tweak == null) {
      tweak = new byte[8];
      new SecureRandom().nextBytes(tweak);
    } else if (tweak.length != 8) {
      throw new IllegalArgumentException("Tweak must be 8 bytes");
    }

    // Encrypt using KIASU-BC
    byte[] ciphertext = kiasuBCEncrypt(key, tweak, ipBytes);

    // Return tweak || ciphertext
    byte[] result = new byte[24];
    System.arraycopy(tweak, 0, result, 0, 8);
    System.arraycopy(ciphertext, 0, result, 8, 16);
    return result;
  }

  /**
   * Decrypt an IP address using ipcrypt-nd.
   *
   * @param encryptedData 24-byte encrypted data (tweak || ciphertext)
   * @param key 16-byte decryption key
   * @return Decrypted IP address
   * @throws Exception if decryption fails
   */
  public static InetAddress decrypt(byte[] encryptedData, byte[] key) throws Exception {
    if (encryptedData.length != 24) { // 8 bytes tweak + 16 bytes ciphertext
      throw new IllegalArgumentException("Encrypted data must be 24 bytes");
    }

    // Split into tweak and ciphertext
    byte[] tweak = Arrays.copyOfRange(encryptedData, 0, 8);
    byte[] ciphertext = Arrays.copyOfRange(encryptedData, 8, 24);

    // Decrypt using KIASU-BC
    byte[] ipBytes = kiasuBCDecrypt(key, tweak, ciphertext);

    // Convert back to IP address
    return IPCryptUtils.bytesToIp(ipBytes);
  }
}
