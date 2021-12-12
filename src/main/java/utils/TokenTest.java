package utils;

import java.io.IOException;
import java.util.concurrent.ExecutionException;

public class TokenTest {
    public static void main(String[] args) throws IOException, ExecutionException, InterruptedException {
        FirebaseUtil fu = new FirebaseUtil();
        System.out.println(fu.getLoginToken("admin"));
    }
}
