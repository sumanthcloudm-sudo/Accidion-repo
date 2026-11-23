import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;

public class Manager {

    private static final String password = System.getenv("ACCIDION_PASSWORD");

    public void getUser(Connection connection, String id) throws Exception {
        String query = "SELECT * FROM users WHERE id = " + id;
        Statement statement = connection.createStatement();
        ResultSet result = statement.executeQuery(query);
    }
}
