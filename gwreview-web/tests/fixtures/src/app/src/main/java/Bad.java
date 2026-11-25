import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
public class Bad extends HttpServlet {
  String password = "Sup3rS3cretPassw0rd!";
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String name = req.getParameter("name");
    Connection c = DriverManager.getConnection("jdbc:postgresql://h/db", "u", "p");
    Statement s = c.createStatement();
    s.executeQuery("SELECT * FROM t WHERE n = '" + name + "'");
    Runtime.getRuntime().exec("ls " + name);
    new ObjectInputStream(req.getInputStream()).readObject();
    java.security.MessageDigest.getInstance("MD5");
  }
}
