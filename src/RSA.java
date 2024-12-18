import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class RSA {
    private static final int BLOCK_SIZE = 6;
    public static BigInteger textToBigInteger(String input) {
        StringBuilder binaryRepresentation = new StringBuilder();

        for (char c : input.toCharArray()) { // Prochází každý znak vstupního textu
            String binary = Integer.toBinaryString(c);
            String resultBinary = String.format("%9s", binary).replace(' ', '0');
            binaryRepresentation.append(resultBinary);
        }

        return new BigInteger(binaryRepresentation.toString(), 2); // 2 znamená, že řetězec je v binární soustavě
    }


    public static String bigIntegerToText(BigInteger number) {
        String binaryRepresentation = number.toString(2); // 2 - převod do *binarního* kódu

        int requiredBits = 9 - (binaryRepresentation.length() % 9);
        if (requiredBits != 9) {
            binaryRepresentation = "0".repeat(requiredBits) + binaryRepresentation;
        }

        StringBuilder text = new StringBuilder();
        for (int i = 0; i < binaryRepresentation.length(); i += 9) {
            String byteString = binaryRepresentation.substring(i, i + 9); // substring(firstIndex, lastIndex)
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



    // (a * x) % m == 1 -> hledáme x
    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger[] egcd = extendedGCD(a, m);
        if (!egcd[2].equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("ModInverse neexistuje");
        }
        return egcd[0].mod(m);
    }

    private static BigInteger[] extendedGCD(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[] {BigInteger.ONE, BigInteger.ZERO, a};
        }

        BigInteger[] values = extendedGCD(b, a.mod(b));
        BigInteger x = values[1];
        BigInteger y = values[0].subtract(a.divide(b).multiply(values[1]));

        return new BigInteger[] {x, y, values[2]};
    }

    public static BigInteger EulerovaFunkce(BigInteger p, BigInteger q) { // phi
        if (p.compareTo(BigInteger.ZERO) <= 0 || q.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("Prvočísla musí být větší než 0");
        }
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static BigInteger find_E(BigInteger p, BigInteger q) {
        BigInteger phiN = EulerovaFunkce(p, q);  // Ф(N) = (p-1) * (q-1)
        SecureRandom rnd = new SecureRandom();
        BigInteger e;

        do {
            e = new BigInteger(phiN.bitLength() - 1, rnd); // e must be less than Ф(N)
            if (e.testBit(0) == false) { // if (generované číslo je liché)
                e = e.add(BigInteger.ONE); // if (sudé) +1 aby bylo liché. To je povinné, protože sudé číslo má vždy společného dělitele s Ф(N) (když Ф(N) taky je sudé)
            }
        } while (!GCD(e, phiN).equals(BigInteger.ONE)); // Cyklus se opakuje, dokud gcd != 1

        return e;
    }

    public static BigInteger GCD(BigInteger a, BigInteger b) {
        while (!b.equals(BigInteger.ZERO)) {
            BigInteger temp = b;
            b = a.mod(b);
            a = temp;
        }
        return a;
    }

    public static BigInteger findPrivateKey(BigInteger e, BigInteger p, BigInteger q) {
        BigInteger phiN = EulerovaFunkce(p, q);
        return modInverse(e, phiN);
    }

    public static BigInteger encrypt(BigInteger message, BigInteger N, BigInteger e) {
        if (message.compareTo(N) >= 0) {
            throw new IllegalArgumentException();
        }
        return message.modPow(e, N);
    }

    public static BigInteger decrypt(BigInteger encryptedMessage, BigInteger N, BigInteger d) {
        if (encryptedMessage.compareTo(N) >= 0) {
            throw new IllegalArgumentException();
        }
        return encryptedMessage.modPow(d, N);
    }

    public static BigInteger generate_p_and_q(int digitCount) {
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
