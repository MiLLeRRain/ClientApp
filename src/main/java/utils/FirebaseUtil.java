package utils;

import com.google.api.core.ApiFuture;
import com.google.auth.oauth2.GoogleCredentials;

import com.google.cloud.firestore.*;
import com.google.common.collect.Lists;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.cloud.FirestoreClient;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;

public class FirebaseUtil {

    private Firestore db;

    static GoogleCredentials authExplicit(String jsonPath) throws IOException {
        // You can specify a credential file by providing a path to GoogleCredentials.
        // Otherwise credentials are read from the GOOGLE_APPLICATION_CREDENTIALS environment variable.
        GoogleCredentials credentials = GoogleCredentials.fromStream(new FileInputStream(jsonPath))
                .createScoped(Lists.newArrayList("https://www.googleapis.com/auth/cloud-platform"));
        return credentials;
    }

    public static Firestore getInstance(GoogleCredentials credentials, String projectID) {
        FirebaseOptions options = new FirebaseOptions.Builder()
                .setCredentials(credentials)
                .setProjectId(projectID)
                .build();
        FirebaseApp.initializeApp(options);

        Firestore db = FirestoreClient.getFirestore();

        return db;
    }

    public void saveData(Firestore db) throws ExecutionException, InterruptedException {
        DocumentReference docRef = db.collection("users").document("alovelace");
        // Add document data  with id "alovelace" using a hashmap
        Map<String, Object> data = new HashMap<>();
        data.put("first", "Ada");
        data.put("last", "Lovelace");
        data.put("born", 1815);
        //asynchronously write data
        ApiFuture<WriteResult> result = docRef.set(data);
        // ...
        // result.get() blocks on response
        // System.out.println("Update time : " + result.get().getUpdateTime());
        result.get();
    }

    public void readData(Firestore db) throws ExecutionException, InterruptedException {
        // asynchronously retrieve all users
        ApiFuture<QuerySnapshot> query = db.collection("userpass").get();
// ...
// query.get() blocks on response
        QuerySnapshot querySnapshot = query.get();
        List<QueryDocumentSnapshot> documents = querySnapshot.getDocuments();
        for (QueryDocumentSnapshot document : documents) {
            System.out.println("Document ID: " + document.getId());
            System.out.println("Username: " + document.getString("username"));
            if (document.contains("middle")) {
                System.out.println("Middle: " + document.getString("middle"));
            }
            System.out.println("Password: " + document.getString("password"));
        }
    }

    public void updateToken() throws ExecutionException, InterruptedException {
        ApiFuture<QuerySnapshot> query = db.collection("loginTokenAutoUpdate").get();
        QuerySnapshot querySnapshot = query.get();
        List<QueryDocumentSnapshot> documents = querySnapshot.getDocuments();

        for (QueryDocumentSnapshot d : documents) {
            String newToken = AESUtil.createAesKey();
            d.getReference().update("loginToken", newToken);
        }
    }

    public FirebaseUtil() throws IOException, ExecutionException, InterruptedException {
        GoogleCredentials gc = authExplicit("src/main/java/cloudkeys/logintokendistribution-ddac4beff72a.json");
        db = getInstance(gc, "logintokendistribution");
    }

    public boolean validateUserPass(String username, String password) throws IOException, ExecutionException, InterruptedException {
        ApiFuture<QuerySnapshot> query = db.collection("userpass").get();
        QuerySnapshot querySnapshot = query.get();
        List<QueryDocumentSnapshot> documents = querySnapshot.getDocuments();
        System.out.println("checking:" + username + "/" + password);
        for (QueryDocumentSnapshot document : documents) {
            System.out.println(document.getString("username"));
            System.out.println(document.getString("password"));
            if (Objects.equals(document.getString("username"), username)) {
                if (Objects.equals(document.getString("password"), password)) {
                    System.out.println("its true");
                    return true;
                }
            }
        }
        System.out.println("its false");
        return false;
    }

    public String getLoginToken(String username) throws ExecutionException, InterruptedException {
        String toReturn = "";
        ApiFuture<QuerySnapshot> query = db.collection("loginTokenAutoUpdate").get();
        QuerySnapshot querySnapshot = query.get();
        List<QueryDocumentSnapshot> documents = querySnapshot.getDocuments();
        for (QueryDocumentSnapshot document : documents) {
            if (document.getId().equals(username)) {
                toReturn = document.getString("loginToken");
            }
        }
        return toReturn;
    }
}
