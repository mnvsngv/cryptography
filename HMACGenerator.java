import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;

public class HMACGenerator {
    final private String hashAlgorithm;
    final private MessageDigest messageDigest;
    final private Map<String, Integer> blockSizesDictionary;
    final private int blockSize;
    
    public HMACGenerator(String hashAlgorithm) throws NoSuchAlgorithmException {
        this.hashAlgorithm = hashAlgorithm;
        messageDigest = MessageDigest.getInstance(hashAlgorithm);
        blockSizesDictionary = generateBlockSizeDictionary();
        blockSize = blockSizesDictionary.get(hashAlgorithm);
    }
    
    private Map<String, Integer> generateBlockSizeDictionary() {
        Map<String, Integer> dictionary = new HashMap<>();
        dictionary.put("MD2", 16);
        dictionary.put("MD5", 64);
        dictionary.put("SHA-1", 64);
        dictionary.put("SHA-256", 64);
        dictionary.put("SHA-384", 64);
        dictionary.put("SHA-512", 128);
        return dictionary;
    }
    
    public byte[] generateMAC(byte[] text, byte[] key, int tagSize) {
        byte[] hmac = generateHMAC(text, key);
        return Arrays.copyOf(hmac, tagSize);
    }
    
    public byte[] generateHMAC(byte[] text, byte[] key) {
        // Steps 1 to 3
        byte[] k0 = getK0(key, blockSize);
        System.out.println("K0:\n" + byteArrayToHexString(k0));
        
        // Step 4: K0 XOR ipad
        byte[] k0XORipad = XOR(k0, createInnerPad(blockSize));
        System.out.println("K0 ^ ipad:\n" + byteArrayToHexString(k0XORipad));
        
        // Step 5 & 6 H((K0 XOR ipad) || text)
        byte[] intermediateHash = hash(concatenateByteArrays(k0XORipad, text));
        System.out.println("Intermediate Hash:\n" + byteArrayToHexString(intermediateHash));
        
        // Step 7: K0 XOR opad
        byte[] k0XORopad = XOR(k0, createOuterPad(blockSize));
        System.out.println("K0 ^ opad:\n" + byteArrayToHexString(k0XORopad));
        
        // Step 8 & 9: H(K0 XOR opad) || H((K0 XOR ipad) || text))
        return hash(concatenateByteArrays(k0XORopad, intermediateHash));
    }
    
    public String byteArrayToHexString(byte[] bytes) {
        StringBuffer buffer = new StringBuffer(bytes.length*2);
        for (int i = 0; i < bytes.length; ++i) {
            buffer.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return buffer.toString();
    }
    
    public byte[] hexStringToByteArray(String input) {
        int len = input.length();
        byte[] data = new byte[len/2];
        for (int i = 0; i < len; i += 2) {
            data[i/2] = (byte) ((Character.digit(input.charAt(i), 16) << 4) + Character.digit(input.charAt(i+1), 16));
        }
        return data;
    }
    
    public byte[] XOR(byte[] left, byte[] right) {
        assert left.length == right.length;
        byte[] buffer = new byte[left.length];
        for (int i = 0; i < left.length; ++i) {
            buffer[i] = (byte) (left[i] ^ right[i]);
        }
        return buffer;
    }
    
    private byte[] hash(byte[] input) {
        return messageDigest.digest(input);
    }
    
    private byte[] concatenateByteArrays(byte[] left, byte[] right) {
        byte[] buffer = new byte[left.length + right.length];
        System.arraycopy(left, 0, buffer, 0, left.length);
        System.arraycopy(right, 0, buffer, left.length, right.length);
        return buffer;
    }
    
    private byte[] getK0(byte[] key, int blockSize) {
        byte[] k0 = new byte[blockSize];
        if (key.length == blockSize) {
            k0 = key;
        } else if (key.length > blockSize) {
            k0 = Arrays.copyOf(hash(key), blockSize);
        } else if (key.length < blockSize) {
            k0 = Arrays.copyOf(key, blockSize);
        }
        return k0;
    }
    
    private byte[] createInnerPad(int blockSize) {
        StringBuffer buffer = new StringBuffer(blockSize*2);
        for (int i = 0; i < blockSize; ++i) {
            buffer.append("36");
        }
        return hexStringToByteArray(buffer.toString());
    }
    
    private byte[] createOuterPad(int blockSize) {
        StringBuffer buffer = new StringBuffer(blockSize*2);
        for (int i = 0; i < blockSize; ++i) {
            buffer.append("5C");
        }
        return hexStringToByteArray(buffer.toString());
    }
}