package utils;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.Scanner;
import java.util.concurrent.ExecutionException;

public class CaesarUtil {

    private static String msg;

    public static void main(String[] args) throws InterruptedException, IOException, ExecutionException {

        while (true) {
            System.out.println("input a word to encrypt.");
            Scanner userInput = new Scanner(System.in);

            while (!userInput.hasNext()) ;

            msg = "";
            if (userInput.hasNext()) msg = userInput.nextLine();

            System.out.println("input is '" + msg + "'");
            if (!msg.equals("")) {
                encrypt(msg.toLowerCase(), 5);
                decrypt(encrypt(msg.toLowerCase(), 5));
            }
            userInput.close();
            Thread.sleep(1000);
        }
    }

    private static String encrypt(String msg, int shift) {
        StringBuilder encrypted = new StringBuilder();
        System.out.println("before encrypt is: " + msg);
        char[] msgCs = msg.toCharArray();
        for (char c : msgCs) {
            if (c == ' ') {
            } else if (c + shift - 'a' > 26) c -= (26 - shift);
            else c = (char) (c + shift);
            encrypted.append(c);
        }
        String output = encrypted.toString();
        System.out.println("encrypted msg: " + output);
        return output;
    }

    public static void decrypt(String msg) {
        System.out.println("before decrypt is: " + msg);
        for (int i = 1; i < 26; i++) {
            StringBuilder decrypted = new StringBuilder();
            char[] msgCs = msg.toCharArray();
            System.out.println("shift: " + i);
            for (char c : msgCs) {
                if (c == ' ') {
                } else if (c - i - 'a' < 0) c += (26 - i);
                else c = (char) (c - i);
                decrypted.append(c);
            }
            System.out.println("decrypted msg: " + decrypted);
            String[] words = decrypted.toString().split("\\s+");
            if (valid(words[0])) {
                break;
            }
            System.out.println("---------------------");
        }
        System.out.println("BINGO!");
    }

    private static boolean valid(String decryptedWord) {
        String params = inflections(decryptedWord);
        if (doInBackground(params) != null) return true;
        return false;
    }

    private static String inflections(String word) {
        final String language = "en";
        final String word_id = word.toLowerCase();
        return "https://od-api.oxforddictionaries.com:443/api/v2/lemmas/" + language + "/" + word_id;
    }

    protected static String doInBackground(String params) {

        //TODO: replace with your own app id and app key
        final String app_id = "497869e7";
        final String app_key = "9b8bc2cb8650a257ae3909b914157e52";
        try {
            URL url = new URL(params);
            HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
            urlConnection.setRequestProperty("Accept", "application/json");
            urlConnection.setRequestProperty("app_id", app_id);
            urlConnection.setRequestProperty("app_key", app_key);

            // read the output from the server
            InputStream input = null;
            try {
                input = urlConnection.getInputStream();
            } catch (Exception e) {
            }
            if (input != null) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(input));
                StringBuilder stringBuilder = new StringBuilder();

                String line = null;
                while ((line = reader.readLine()) != null) {
                    stringBuilder.append(line + "\n");
                }

                return stringBuilder.toString();
            }

            return null;

        } catch (Exception e) {
            e.printStackTrace();
            return e.toString();
        }
    }

}
