package utils;

import lombok.SneakyThrows;

import java.io.IOException;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutionException;

public class LoginTokenAutoUpdater {

    public static void main(String[] args) throws IOException, ExecutionException, InterruptedException {
        // Construct the timer
        Timer timer = new Timer();
        System.out.println("Starting from: "+new Date());
        // starting from 3000ms, run every 86400000ms / 24 hours;
        timer.schedule(new TokenUpdater(),3000,86400000);
    }
}

/**
 * Timed Task
 */
class TokenUpdater extends TimerTask{

    // function to be called back
    FirebaseUtil fu = new FirebaseUtil();

    TokenUpdater() throws IOException, ExecutionException, InterruptedException {
    }

    @SneakyThrows
    public void run() {

        System.out.println("Hello. Current time is: "+new Date());
        System.out.println("Old login token is: " + fu.getLoginToken("admin"));
        fu.updateToken();
        Thread.sleep(2000);
        System.out.println("New login token is: " + fu.getLoginToken("admin"));
        System.out.println("------------------------------------------------------");
    }

}