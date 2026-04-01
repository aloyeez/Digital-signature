import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class RSA {
    private static final int BLOCK_SIZE = 6;

    public static BigInteger textToBigInteger(String input) {
        StringBuilder binaryRepresentation = new StringBuilder();

        for (char c : input.toCharArray()) {
            String binary = Integer.toBinaryString(c);
            String resultBinary = String.format("%9s", binary).replace(' ', '0');
            binaryRepresentation.append(resultBinary);
        }

        return new BigInteger(binaryRepresentation.toString(), 2);
    }

    public static String bigIntegerToText(BigInteger number) {
        String binaryRepresentation = number.toString(2);

        int requiredBits = 9 - (binaryRepresentation.length() % 9);
        if (requiredBits != 9) {
            binaryRepresentation = "0".repeat(requiredBits) + binaryRepresentation;
        }

        StringBuilder text = new StringBuilder();
        for (int i = 0; i < binaryRepresentation.length(); i += 9) {
            String byteString = binaryRepresentation.substring(i, i + 9);
            int asciiCode = Integer.parseInt(byteString, 2);
            text.append((char) asciiCode);
        }

        return text.toString();
    }

    public static List<String> splitIntoBlocks(String message) {
        List<String> blocks = new ArrayList<>();
        for (int i = 0; i < message.length(); i += BLOCK_SIZE) {
            int endIndex = Math.min(i + BLOCK_SIZE, message.length());
            String block = message.substring(i, endIndex);
            if (block.length() < BLOCK_SIZE) {
                block = String.format("%-" + BLOCK_SIZE + "s", block);
            }
            blocks.add(block);
        }
        return blocks;
    }

    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger[] egcd = extendedGCD(a, m);
        if (!egcd[2].equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("Modular inverse does not exist");
        }
        return egcd[0].mod(m);
    }

    private static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{BigInteger.ONE, BigInteger.ZERO, a};
        }

        BigInteger[] values = extendedGCD(b, a.mod(b));
        BigInteger x = values[1];
        BigInteger y = values[0].subtract(a.divide(b).multiply(values[1]));

        return new BigInteger[]{x, y, values[2]};
    }

    public static BigInteger eulerTotient(BigInteger p, BigInteger q) {
        if (p.compareTo(BigInteger.ZERO) <= 0 || q.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("Primes must be greater than 0");
        }
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static BigInteger findPublicExponent(BigInteger p, BigInteger q) {
        BigInteger phiN = eulerTotient(p, q);
        SecureRandom rnd = new SecureRandom();
        BigInteger e;

        do {
            e = new BigInteger(phiN.bitLength() - 1, rnd);
            if (!e.testBit(0)) {
                e = e.add(BigInteger.ONE);
            }
        } while (!gcd(e, phiN).equals(BigInteger.ONE));

        return e;
    }

    public static BigInteger gcd(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    public static BigInteger findPrivateKey(BigInteger e, BigInteger p, BigInteger q) {
        BigInteger phiN = eulerTotient(p, q);
        return modInverse(e, phiN);
    }

    public static BigInteger encrypt(BigInteger message, BigInteger N, BigInteger e) {
        if (message.compareTo(N) >= 0) {
            throw new IllegalArgumentException("Message must be smaller than modulus N");
        }
        return message.modPow(e, N);
    }

    public static BigInteger decrypt(BigInteger encryptedMessage, BigInteger N, BigInteger d) {
        if (encryptedMessage.compareTo(N) >= 0) {
            throw new IllegalArgumentException("Ciphertext must be smaller than modulus N");
        }
        return encryptedMessage.modPow(d, N);
    }

    public static BigInteger generatePrime(int digitCount) {
        SecureRandom random = new SecureRandom();
        BigInteger result;

        BigInteger min = BigInteger.TEN.pow(digitCount - 1);
        BigInteger max = BigInteger.TEN.pow(digitCount).subtract(BigInteger.ONE);

        do {
            result = new BigInteger(max.subtract(min).bitLength(), random);
            result = result.add(min);
        } while (!result.isProbablePrime(100));

        return result;
    }
}
