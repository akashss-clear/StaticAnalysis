import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.util.Base64;
import java.util.logging.*;
import java.net.URL;
import java.net.HttpURLConnection;

public class VulnerableApp extends HttpServlet {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/app_db"; // Hardcoded DB URL
    private static final String DB_USER = "admin"; // Hardcoded credentials
    private static final String DB_PASSWORD = "password123"; // Hardcoded password

    // Logger without proper validation/sanitization
    private static final Logger logger = Logger.getLogger(VulnerableApp.class.getName());

    //===========================================
    // OWASP Vulnerability 1: SQL Injection
    //===========================================
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Vulnerable SQL query (user input directly concatenated into SQL query)
        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement statement = connection.createStatement()) {

            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            ResultSet resultSet = statement.executeQuery(query);

            if (resultSet.next()) {
                logger.info("User authenticated: " + username);
                response.getWriter().println("Login successful");
            } else {
                response.getWriter().println("Login failed");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    //============================================
    // OWASP Vulnerability 2: Cross-Site Scripting (XSS)
    //============================================
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String searchQuery = request.getParameter("search");

        // Vulnerable to XSS (user input is reflected in response without escaping)
        response.getWriter().println("Search results for: " + searchQuery);
    }

    //============================================
    // OWASP Vulnerability 3: Insecure Deserialization
    //============================================
    protected void doPostDeserialize(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());

        try {
            // Vulnerable to malicious serialized objects
            Object obj = ois.readObject();
            response.getWriter().println("Object deserialized: " + obj.toString());
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
        }
    }

    //============================================
    // OWASP Vulnerability 4: Weak Encoding (Sensitive Data Exposure)
    //============================================
    protected void doGetEncode(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String sensitive = "HardcodedSecretValue123"; // Sensitive information

        // Weak Base64 encoding of sensitive data
        String encoded = Base64.getEncoder().encodeToString(sensitive.getBytes());
        response.getWriter().println("Encoded value: " + encoded);
    }

    //============================================
    // OWASP Vulnerability 5: Command Injection
    //============================================
    protected void doGetCommand(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String ip = request.getParameter("ip");

        // Vulnerable to command injection (user input directly used in command)
        String command = "ping -c 4 " + ip;

        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

        String line;
        while ((line = reader.readLine()) != null) {
            response.getWriter().println(line);
        }
    }

    //============================================
    // OWASP Vulnerability 6: Server-Side Request Forgery (SSRF)
    //============================================
    protected void doGetSSRF(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String targetURL = request.getParameter("url");

        // Allowing user input in a URL request
        URL url = new URL(targetURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        while ((inputLine = in.readLine()) != null) {
            response.getWriter().println(inputLine);
        }
        in.close();
    }

    //============================================
    // OWASP Vulnerability 7: Security Misconfiguration
    //============================================
    @Override
    protected void init() throws ServletException {
        super.init();

        // Enable debug mode (exposes sensitive configurations in logs)
        logger.setLevel(Level.ALL);
        logger.info("Debug mode enabled.");
    }
}