import java.math.BigInteger;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.io.*;
import javax.xml.bind.DatatypeConverter;


public class Assignment1 {

    private static String pMod = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd" +
            "ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc" +
            "8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f" +
            "47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";

    private static String gen = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2" +
            "e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864" +
            "1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496" +
            "64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";

    private static String pubKeyA = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1" +
            "b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111" +
            "d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15" +
            "171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";

    /*
        Based on pseudo code
            y = 1
            for i = n-1 downto 0 do
                y = (y*y) mod p
                if xi = 1 then y = (y*a) mod p
            end
        from lecture notes "Number Theory 1" page 10

     */
    private static BigInteger modEx(BigInteger a, BigInteger x, BigInteger mod) {
        int n = x.bitLength();

        BigInteger y = BigInteger.ONE;
        for (int i = n - 1; i >= 0; i--) {
            y = y.multiply(y).mod(mod);
            //check if bit is set to 1
            if (x.testBit(i)) {
                y = y.multiply(a).mod(mod);
            }
        }
        return y;
    }


    public static void main(String[] args) {

        String fileName = (args[0]);

        //private key
        BigInteger b = new BigInteger(1023, new SecureRandom());

        //provided public key
        BigInteger A = new BigInteger(pubKeyA, 16);

        // prime modulus
        BigInteger p = new BigInteger(pMod, 16);

        //generator g
        BigInteger g = new BigInteger(gen, 16);

        //personal public key
        BigInteger B = modEx(g, b, p);

        //shared key
        BigInteger s = modEx(A, b, p);

        try {

            //attempt to create AES key k(256 bit size) using the shared key generated above
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] xx = messageDigest.digest(s.toByteArray());
            SecretKeySpec preK = new SecretKeySpec(xx, "AES");
            SecretKey k = preK;

            //create the 128-bit IV in hex
            byte[] preIV = new byte[16];
            SecureRandom randomNum = new SecureRandom();
            randomNum.nextBytes(preIV);
            IvParameterSpec iv = new IvParameterSpec(preIV);

            //initialise the cipher
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, k, iv);

            //read in the file you want to encrypt
            File input = new File(fileName);
            int lengthInput = (int) input.length();
            int lengthPadding = 16 - (lengthInput % 16);
            byte[] fileAsBytes = new byte[lengthInput + lengthPadding];
            FileInputStream fInStream = new FileInputStream(input);
            fInStream.read(fileAsBytes);
            fInStream.close();

            //padding input based on lecture notes/assignment spec
            fileAsBytes[lengthInput] = (byte) 128;
            for(int i = 1; i < lengthPadding; i++){
                fileAsBytes[lengthInput + 1] = (byte) 0;
            }

            // encrypt the padded input, as a byte array
            byte[] finalOut = c.doFinal(fileAsBytes);

            //write the encrypted data to a file
            File outputFile = new File("outputFile");
            FileOutputStream fOut = new FileOutputStream(outputFile);
            fOut.write(finalOut);
            fOut.close();
            System.out.println("Encryption completed");

            //printing byte array as hex based on code seen here
            // https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
            StringBuilder stringBuilder = new StringBuilder(preIV.length * 2);
            for(byte a:preIV){
                stringBuilder.append(String.format("%02x", a & 0xff));
            }
            System.out.println("IV: " + stringBuilder.toString());

            String pubKeyHEX = B.toString(16);
            System.out.println("My public key: " + pubKeyHEX);




        } catch (NoSuchAlgorithmException | IOException | NoSuchPaddingException | InvalidKeyException
                | BadPaddingException | IllegalBlockSizeException |
                InvalidAlgorithmParameterException e){ System.out.print("Error: " + e);

    }
}


}
