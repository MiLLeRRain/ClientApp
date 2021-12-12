package utils;



import org.apache.xerces.util.DOMUtil;
import org.w3c.dom.Document;
import org.xml.sax.ContentHandler;

import javax.xml.crypto.dsig.XMLObject;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PostgresJDBC {

    public PostgresJDBC() {

        try {
            Connection connection = null;
            String databaseUser = "admin";
            String databasePass = "p1a2s3s4w5o6r7d8";
            Class.forName("com.mysql.cj.jdbc.Driver");
            String url = "jdbc:mysql://database-1.c2jsskezjm38.ap-southeast-2.rds.amazonaws.com:3306/breakfast_menu";
            connection = DriverManager.getConnection(url, databaseUser, databasePass);

            Statement stmt = connection.createStatement();
            String query = "select * from food";
            String query2 = "SELECT " +
                    "name AS 'name', " +
                    "price AS 'price', " +
                    "description AS 'description', " +
                    "calories AS 'calories', " +
                    "FROM food " +
                    "FOR XML PATH('fooo');";


//          SELECT * FROM userdata order by cleanliness DESC, socially_active DESC, eco_conciousness DESC;
            ResultSet rs = stmt.executeQuery(query);

//            while (rs.next()) {
//                String name = rs.getString("name");
//                String price = rs.getString("price");
//                String desc = rs.getString("description");
//                String calories = rs.getString("calories");
//                System.out.println(name + "\n" + price +  "\n" + desc +  "\n" + calories);
//                System.out.println("----");
//            }

            // Convert ResultSet to Dom
            Document tempDoc = ResultSet2Dom.toDocument(rs);
            // Convert Dom tp XML
            String xmlString = DOM2XML(tempDoc);
            System.out.println(DOM2XML(tempDoc));

//            d2x.generateXML(tempDoc, new File("./assets/food.xml"));

            FileWriter fw = new FileWriter("src/main/java/assets/food.xml");
            fw.write(xmlString);
            fw.close();


            rs.close();
            connection.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String DOM2XML (Document doc)
    {
        String xmlString=null;
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            StreamResult result = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(doc);
            transformer.transform(source, result);
            xmlString = result.getWriter().toString();
        } catch (TransformerException ex) {
            Logger.getLogger(DOMUtil.class.getName()).log(Level.SEVERE, null, ex);
            xmlString=null;
        }
        return xmlString;
    }
    public static void main(String[] args) {
        new PostgresJDBC();
    }
}
