package security.assignment;

import java.util.*;
import java.math.*;

public class SecurityAssignment {

    // 1. Cyber Double Transposition with One-Time Pad Methods
    // 1.1 returning the encrypted text for the first cryptographic algorithm
    public static String doubleTranspositionEncryption(String text, String key) {
        StringBuilder cipherText = new StringBuilder();

        // calculate the number of rows required for the key
        int numRows = (int) Math.ceil((double) text.length() / key.length());

        // Perform the first transposition using the key
        char[] sortedKey = key.toCharArray();
        Arrays.sort(sortedKey);

        // 1st transposition: sort characters in each row according to the sorted key
        char[][] matrix = new char[numRows][key.length()];
        for (int row = 0; row < numRows; row++) {
            for (int col = 0; col < key.length(); col++) {
                int index = row * key.length() + col;
                if (index < text.length()) {
                    matrix[row][col] = text.charAt(index);
                } else {
                    matrix[row][col] = ' ';
                }
            }
        }

        // read column-wise as per sorted key order
        for (char keyChar : sortedKey) {
            int colIndex = key.indexOf(keyChar);
            for (int row = 0; row < numRows; row++) {
                cipherText.append(matrix[row][colIndex]);
            }
        }

        return cipherText.toString();
    }

    // 1.2 returning the decrypted text for the first cryptographic algorithm
    public static String doubleTranspositionDecryption(String cipherText, String key) {
        StringBuilder plainText = new StringBuilder();

        // calculate the number of rows required for the key
        int numRows = (int) Math.ceil((double) cipherText.length() / key.length());

        // perform the second transposition using the sorted key
        char[] sortedKey = key.toCharArray();
        Arrays.sort(sortedKey);

        // read column-wise as per sorted key order to build matrix
        char[][] matrix = new char[numRows][key.length()];
        int index = 0;
        for (char keyChar : sortedKey) {
            int colIndex = key.indexOf(keyChar);
            for (int row = 0; row < numRows; row++) {
                matrix[row][colIndex] = cipherText.charAt(index++);
            }
        }

        // read row-wise to get the plain text
        for (int row = 0; row < numRows; row++) {
            for (int col = 0; col < key.length(); col++) {
                plainText.append(matrix[row][col]);
            }
        }

        return plainText.toString().trim();
    }

    // 2. Diffie-Hellman Key Exchange
    // 2.1 returning the value of x ^ y mod P for the second cryptographic algorithm
    private static long calculatePower(long x, long y, long P) {
        long result = 1;
        x = x % P;
        while (y > 0) {
            if ((y & 1) == 1) {
                result = (result * x) % P;
            }
            y = y >> 1;
            x = (x * x) % P;
        }
        return result;
    }

    // 3. RSA Encryption and Decryption methods
    // 3.1 returning the privite key for the third cryptographic algorithm
    private static int calculatePrivateKey(int p, int q, int e) {
        int phi = (p - 1) * (q - 1);

        // convert e and phi to BigInteger
        BigInteger eBigInteger = BigInteger.valueOf(e);
        BigInteger phiBigInteger = BigInteger.valueOf(phi);

        // calculate the modular multiplicative inverse of e mod phi(n)
        BigInteger dBigInteger = eBigInteger.modInverse(phiBigInteger);

        return dBigInteger.intValue();
    }

    // 3.2 returning the encrypted text for the third cryptographic algorithm
    public static String rsaEncryption(int p, int q, int e, String message) {
        int n = p * q;
        StringBuilder ciphertext = new StringBuilder();

        // iterate over each character in the message to encrypt the text
        for (int i = 0; i < message.length(); i++) {
            char c = message.charAt(i);
            BigInteger m = BigInteger.valueOf((int) c);
            BigInteger encrypted = m.modPow(BigInteger.valueOf(e), BigInteger.valueOf(n));
            ciphertext.append(encrypted).append(" ");
        }
        return ciphertext.toString().trim();
    }

    // 3.3 returning the decrypted text for the third cryptographic algorithm
    public static String rsaDecryption(int p, int q, int e, String ciphertext) {
        int n = p * q;
        int d = calculatePrivateKey(p, q, e);
        StringBuilder plaintext = new StringBuilder();
        String[] encryptedChars = ciphertext.split(" ");

        // iterate over each character in the message to decrypt the text
        for (String encryptedChar : encryptedChars) {
            BigInteger encrypted = new BigInteger(encryptedChar);
            BigInteger decrypted = encrypted.modPow(BigInteger.valueOf(d), BigInteger.valueOf(n));
            char plaintextChar = (char) decrypted.intValue();
            plaintext.append(plaintextChar);
        }
        return plaintext.toString();
    }

    // driver method
    public static void main(String[] args) {
        Scanner input = new Scanner(System.in);
        char choose = ' ';
        char c;
        while (choose != '0') {
            System.out.println("-------------------------------------------------------------------------------------");
            System.out.println("-----------------------------Please Select Your Action :-----------------------------");
            System.out.println("-----------------------------------Enter 1 To Login----------------------------------");
            System.out.println("-----------------------------------Enter 0 To Exit-----------------------------------");
            System.out.println("-------------------------------------------------------------------------------------");
            choose = input.next().charAt(0);
            if (choose == '1') {
                System.out.println("----------------------------Welcome To Security Assignment----------------------------");
                System.out.println("--------------------------Select The Cryptographic Algorithm--------------------------");
                System.out.println("write 1 for Cyber Double Transposition with One-Time Pad");
                System.out.println("write 2 for Diffie-Hellman Key Exchange");
                System.out.println("write 3 for RSA Encryption and Decryption");
                System.out.println("-------------------------------------------------------------------------------------");
                c = input.next().charAt(0);
                switch (c) {
                    case '1':
                        String userString, key;
                        System.out.println("Cryptographic Using Cyber Double Transposition with One-Time Pad");

                        // get text inputs from the user                                              
                        System.out.println("Enter text to encrypt it:");
                        input.nextLine();
                        userString = input.nextLine();
                        System.out.println("Enter key:");
                        key = input.nextLine();

                        // call encryption and decryption methods
                        String encryptedText = doubleTranspositionEncryption(userString, key);
                        String decryptedText = doubleTranspositionDecryption(encryptedText, key);

                        // print results
                        System.out.println("Plain Text: " + userString);
                        System.out.println("Cipher Text: " + encryptedText);
                        System.out.println("Decrypted Text: " + decryptedText);
                        break;
                    case '2':
                        long G, P, a, b, keyA, keyB;
                        System.out.println("Cryptographic Using Diffie-Hellman Key Exchange");

                        // get inputs for public keys from the user 
                        System.out.println("Enter value for public key G:");
                        G = input.nextLong();
                        System.out.println("Enter value for public key P:");
                        P = input.nextLong();

                        // get input from user for private keys a and b selected by User 1 and User 2  
                        System.out.println("Enter value for private key a selected by user 1:");
                        a = input.nextLong();
                        System.out.println("Enter value for private key b selected by user 2:");
                        b = input.nextLong();

                        // calculate A and B keys 
                        long A = calculatePower(G, a, P);
                        long B = calculatePower(G, b, P);

                        // calculate secret keys
                        keyA = calculatePower(B, a, P);
                        keyB = calculatePower(A, b, P);

                        // print results
                        System.out.println("Secret key for User 1 is: " + keyA);
                        System.out.println("Secret key for User 2 is: " + keyB);
                        break;
                    case '3':
                        String message;
                        int p = 61, q = 53, e = 7;
                        System.out.println("Cryptographic Using RSA Encryption and Decryption");

                        // get text inputs from the user 
                        System.out.println("Enter text to encrypt it:");
                        input.nextLine();
                        message = input.nextLine();

                        // call encryption and decryption methods
                        String ciphertext = rsaEncryption(p, q, e, message);
                        String decryptedMessage = rsaDecryption(p, q, e, ciphertext);

                        // print results
                        System.out.println("Plain text: " + message);
                        System.out.println("Cipher text: " + ciphertext);
                        System.out.println("Decrypted text: " + decryptedMessage);
                        break;
                }
            }
        }
         input.close();
    }

}
