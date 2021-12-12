package client;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Pair;
import lombok.SneakyThrows;
import org.springframework.boot.configurationprocessor.json.JSONException;
import org.springframework.boot.configurationprocessor.json.JSONObject;
import utils.AESUtil;
import utils.KeyPairGenUtil;
import utils.RSAUtil;

import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Optional;
import java.util.Scanner;

public class ClientUI extends Application {

    AnchorPane root =  new AnchorPane();
    TextArea msgFromServer = new TextArea();
    Button sendPubKey;
    Button loginBtn;
    MenuButton autoLogin;
    VBox box2;
    TextArea chatArea;
    TextField inputField;
    Label nameLabel;

    // I/O handlers
    PrintWriter outputPW;
    BufferedReader inputBR;

    String username = "admin";
    String receiverName = "customer";

    String serverAddress = "127.0.0.1";
    int remotePort = 9090;
    Socket clientSocket = null;

    ChatListener chatListener;

    /**
     * Keys
     */
    private String publicKey = "";
    private String privateKey = "";
    private String AESkey = "";
    private String loginToken = "empty";


    @Override
    public void start(Stage stage) throws Exception {

        readLocalLoginToken();

        root.setStyle("-fx-background-color: #9bfe32");

        buildDialogBar();
        buildChatBar();
        buildButtonBar();

        Scene scene =  new Scene(root);
        scene.setOnKeyPressed(new EventHandler<KeyEvent>() {
            @SneakyThrows
            @Override
            public void handle(KeyEvent event) {
                sendChat();
            }
        });
        stage.setScene(scene);
        stage.setWidth(800);
        stage.setHeight(800);

        stage.show();
    }

    private void buildButtonBar() {
        sendPubKey = new Button("SendRSAKey");
        sendPubKey.setOnAction(a -> {
            try {
                if (AESkey.isEmpty()) {
                    // First Connection
                    clientSocket = new Socket(serverAddress, remotePort);
                    outputPW = new PrintWriter(clientSocket.getOutputStream(), true);
                    buildKeys();
                    showReplyFromServer();
                } else {
                    popAlert("Encrypt Keys are prepared.", "No need to rebuild key sets again.");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        loginBtn = new Button("Login");
        loginBtn.setOnAction(a -> {
            try {
                login();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        autoLogin = new MenuButton("AUTO-Login");
        MenuItem miAdmin = new MenuItem("admin");
        MenuItem miCustomer = new MenuItem("customer");

        autoLogin.getItems().addAll(miAdmin, miCustomer);

        miAdmin.setOnAction(a -> {
            try {
                autoLoginGo("admin");
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        miCustomer.setOnAction(a -> {
            try {
                autoLoginGo("customer");
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        ButtonBar bb = new ButtonBar();
        bb.getButtons().addAll(sendPubKey, loginBtn, autoLogin);

        root.getChildren().add(bb);
        root.setTopAnchor(bb, 10.0);
        root.setLeftAnchor(bb, 10.0);


    }

    private void autoLoginGo(String username) throws Exception {
        if (AESkey != "") {
            if (username.equals("admin")) {
                validate(username, "p1a2s3s4", "autoLogin");
            } else if (username.equals("customer")) {
                validate(username, "password", "autoLogin");
            }
            showReplyFromServer();
        }
        else {
            popAlert("No AESKey", "Send RSAKey first");
        }
    }

    /**
     * Build login Dialog
     */
    private void login() throws Exception {
        if (AESkey != "") {
//            clientSocket = new Socket();
////            clientSocket.bind(new InetSocketAddress("127.0.0.1",58295));
//            clientSocket.connect(new InetSocketAddress(serverAddress, remotePort));
            loginDialog();
            showReplyFromServer();
//            clientSocket.close();
        }
        else {
            popAlert("No AESKey", "Send RSAKey first");
        }
    }

    /**
     * Build up the loginDialog
     */
    private void loginDialog() {
        // Create the custom dialog.
        Dialog<Pair<String, String>> dialog = new Dialog<>();
        dialog.setTitle("Login Dialog");
        dialog.setHeaderText("Login Dialog");

// Set the icon (must be included in the project).
//        dialog.setGraphic(new ImageView(Objects.requireNonNull(this.getClass().getResource("./assets/login.png")).toString()));

// Set the button types.
        ButtonType loginButtonType = new ButtonType("Login", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(loginButtonType, ButtonType.CANCEL);

// Create the username and password labels and fields.
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(20, 150, 10, 10));

        TextField username = new TextField();
        username.setPromptText("Username");
        PasswordField password = new PasswordField();
        password.setPromptText("Password");

        grid.add(new Label("Username:"), 0, 0);
        grid.add(username, 1, 0);
        grid.add(new Label("Password:"), 0, 1);
        grid.add(password, 1, 1);

// Enable/Disable login button depending on whether a username was entered.
        Node loginButton = dialog.getDialogPane().lookupButton(loginButtonType);
        loginButton.setDisable(true);

// Do some validation (using the Java 8 lambda syntax).
        username.textProperty().addListener((observable, oldValue, newValue) -> {
            loginButton.setDisable(newValue.trim().isEmpty());
        });

        dialog.getDialogPane().setContent(grid);

// Request focus on the username field by default.
        Platform.runLater(() -> username.requestFocus());

// Convert the result to a username-password-pair when the login button is clicked.
        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == loginButtonType) {
                return new Pair<>(username.getText(), password.getText());
            }
            return null;
        });

        Optional<Pair<String, String>> result = dialog.showAndWait();

        result.ifPresent(usernamePassword -> {
            try {
                validate(username.getText(), password.getText(), "login");
            } catch (Exception e) {
                e.printStackTrace();
            }
            System.out.println("Username=" + username.getText() + ", Password=" + password.getText());
        });
    }

    /**
     * Send to server to validate
     * @param name username
     * @param pass password
     */
    private void validate(String name, String pass, String header) throws Exception {
        username = name;
        HashMap<String, String> namepass = new HashMap<>();
        name = AESUtil.encryptByECB(name, AESkey);
        pass = AESUtil.encryptByECB(pass, AESkey);
        namepass.put("username", name); namepass.put("password", pass);
        JSONObject jsonUserPass = new JSONObject(namepass);

        JSONObject outputJson = packJson(header, jsonUserPass, loginToken);
        outputPW.println(outputJson);
    }

    /**
     * Dialog panel shows the reply from server
     */
    private void buildDialogBar() {
        VBox box1 = new VBox();

        Label label = new Label("The server said:");
        label.setStyle("-fx-background-color: #FFFFFF00");
        msgFromServer = new TextArea("Reply from Server");
        msgFromServer.setPrefSize(650, 200);
        box1.getChildren().addAll(label, msgFromServer);

        root.getChildren().add(box1);
        root.setTopAnchor(box1, 300.0);
        root.setLeftAnchor(box1, 10.0);
    }

    private void buildChatBar() {
        box2 = new VBox();
        box2.setPrefSize(650, 230);
        HBox hb2 = new HBox();
        chatArea = new TextArea();
        chatArea.setPrefSize(500, 200);
        VBox sideBox = new VBox();
        sideBox.prefWidth(150);
        sideBox.setAlignment(Pos.CENTER);
        sideBox.setSpacing(10);
        Label lbl = new Label("USERNAME:");
        Label lbl2 = new Label("RECEIVER:");
        Label lbl3 = new Label();
        nameLabel = new Label();
        MenuButton friendList = new MenuButton("Friends");
        MenuItem m1 = new MenuItem("admin");
        MenuItem m2 = new MenuItem("customer");
        friendList.getItems().addAll(m1, m2);
        m1.setOnAction(a -> {receiverName = "admin"; lbl3.setText(receiverName);});
        m2.setOnAction(a -> {receiverName = "customer"; lbl3.setText(receiverName);});
        Button onlineBtn = new Button("Online");
        sideBox.getChildren().addAll(lbl, nameLabel, friendList, lbl2, lbl3);
        hb2.getChildren().addAll(chatArea, sideBox);
        HBox hb = new HBox();
        inputField = new TextField();
        inputField.setPrefSize(420, 30);
        Button sendBth = new Button("SEND");
        sendBth.setPrefSize(80, 30);
        sendBth.setOnAction(a -> {
            try {
                sendChat();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        hb.getChildren().addAll(inputField, sendBth);
        box2.getChildren().addAll(hb2, hb);

        root.getChildren().add(box2);
        root.setLeftAnchor(box2, 10.0);
        root.setTopAnchor(box2, 10.0);

        box2.setVisible(false);
    }

    private void showReplyFromServer() throws Exception {
        inputBR = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        String answer = inputBR.readLine();
        System.out.println("I hear the server said: "+answer);
        updateMsgField(answer);
        processInput(answer);
    }

    private void processInput(String answer) throws Exception {
        JSONObject inputJson = new JSONObject(answer);
        String header = (String) inputJson.get("header");
        String data = (String) inputJson.get("data");

        switch (header) {
            case "AESKey" :
                updateAESKey(data);
                Platform.runLater(() -> keyAlert());
                break;
            case "validLogin":
                updateLoginToken(data);
                Platform.runLater(() -> {
                    try {
                        validAlert();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
                break;
            case "invalidLogin":
                Platform.runLater(() -> popAlert("Invalid login credentials.", "Check and try to login again."));
                break;
            case "validAutoLogin":
                Platform.runLater(() -> {
                    try {
                        validAlert();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
                break;
            case "incomingMsg":
                readChat(data);
                break;
        }
    }

    private void readChat(String data) throws Exception {
        String decryptChatData = AESUtil.decryptByECB(data, AESkey);
        JSONObject chatData = new JSONObject(decryptChatData);
        String sender = (String) chatData.get("sender");
        String sendTime = (String) chatData.get("sendTime");
        String msg = (String) chatData.get("msg");
        updateChatArea(sender, sendTime, msg);
    }

    private void keyAlert() {
        popAlert("Key sets updated, registration done", "You may login now.");
        sendPubKey.setVisible(false);
    }

    private void validAlert() throws IOException {
        popAlert("Login passed.", "You may use the other Client functions.");
        loginBtn.setVisible(false);
        autoLogin.setVisible(false);
        nameLabel.setText(username);
        box2.setVisible(true);
        chatListener = new ChatListener();
        new Thread(chatListener).start();
    }

    private void sendChat() throws Exception {
        HashMap<String, String> chats = new HashMap<>();
        chats.put("sender", username);
        chats.put("receiver", receiverName);
        chats.put("time", new Date().toString());
        String msg = readInput();
        chats.put("msg", msg);
        System.out.println("Send from client "+msg+" KEY "+AESkey);
        JSONObject chatData = new JSONObject(chats);
        // Encrypt the msg Json here
        String encryptedChats = AESUtil.encryptByECB(chatData.toString(), AESkey);

        // Send to the server
        JSONObject outJson = packJson("chat", encryptedChats, "");
        System.out.println(" Send to server "+outJson);

        // Output the chatJson
        outputPW.println(outJson);
    }

    private String readInput() {
        String msg = inputField.getText();
        inputField.clear();
        updateChatArea(username, new Date().toString(), msg);
        return msg;
    }

    private void updateChatArea(String username, String sendTime, String msg) {
        if (!chatArea.getText().isEmpty()) {
            chatArea.appendText("\n");
        }
        chatArea.appendText(username + " @ ");
        chatArea.appendText(sendTime + ":\n");
        chatArea.appendText(msg + "\n");

        chatArea.setScrollTop(Double.MAX_VALUE);
    }

    private void updateLoginToken(String data) throws Exception {
        loginToken = AESUtil.decryptByECB(data, AESkey);
        writeLocalLoginToken(loginToken);
    }

    private void writeLocalLoginToken(String loginToken) throws IOException {
        Writer w = null;
        try {
            w = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream("src/main/java/cloudkeys/localLoginToken"), "utf-8"));
            w.write(loginToken);
        } finally {
            assert w != null;
            w.close();
        }
    }

    private void readLocalLoginToken() throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader("src/main/java/cloudkeys/localLoginToken"));
        loginToken = reader.readLine();
        System.out.println("localLoginToken: " + loginToken);
    }

    private void updateAESKey(String data) throws Exception {
        AESkey = RSAUtil.decrypt(data, privateKey);
    }

    public void buildKeys() throws NoSuchAlgorithmException, IOException, JSONException {
        String[] keys = KeyPairGenUtil.genKeyPair();
        publicKey = keys[0];
        privateKey = keys[1];
        // Send pub key to server
        JSONObject outJson = packJson("pubKey", publicKey, loginToken);

        System.out.println(outJson.get("data"));
        outputPW.println(outJson);
    }

    private void updateMsgField(String answer) {
        Platform.runLater(() ->
        {
            if (!msgFromServer.getText().isEmpty()) {
                msgFromServer.appendText("\n");
            }
            msgFromServer.appendText(new Date() + ":\n");
            msgFromServer.appendText(answer + "\n");
            msgFromServer.setScrollTop(Double.MAX_VALUE);
        });
    }

    private void popAlert(String header, String content) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setHeaderText(header);
        alert.setContentText(content);
        alert.show();
    }

    private JSONObject packJson(String header, Object data, String encryptToken) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("header", header);
        json.put("data", data);
        json.put("token", encryptToken);

        return json;
    }

    public static void main(String[] args) throws IOException {
        launch(args);
    }

    private class ChatListener implements Runnable {

        public ChatListener() {

        }

        @SneakyThrows
        @Override
        public void run() {
            String chatIn;
            while(clientSocket.isConnected()) {
                if ((chatIn = inputBR.readLine()) == null) continue;
                processInput(chatIn);
            }
        }
    }
}
