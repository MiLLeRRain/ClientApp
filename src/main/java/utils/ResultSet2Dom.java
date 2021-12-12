package utils;

import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;

@Component("xmlMaker")
public class ResultSet2Dom {

    public static Document toDocument(ResultSet rs)
            throws ParserConfigurationException, SQLException
    {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder        = factory.newDocumentBuilder();
        Document doc                   = builder.newDocument();

        ResultSetMetaData rsmd = rs.getMetaData();

        Element results = doc.createElement(rsmd.getCatalogName(1));
        doc.appendChild(results);


        int colCount           = rsmd.getColumnCount();

        while (rs.next())
        {
            Element row = doc.createElement(rsmd.getTableName(1));
            results.appendChild(row);

            for (int i = 1; i <= colCount; i++)
            {
                String columnName = rsmd.getColumnName(i);
                Object value      = rs.getObject(i);

                Element node      = doc.createElement(columnName);
                node.appendChild(doc.createTextNode(value.toString()));
                row.appendChild(node);
            }
        }
        return doc;
    }
}
