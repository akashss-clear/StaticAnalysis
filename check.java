import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

public class SecureHttpClient {
    // Allowlist of domains
    private static final String[] ALLOWED_DOMAINS = {"https://trusted.com", "https://api.example.com"};

    public static void makeRequest(String userProvidedUrl) throws Exception {
        if (!isValidUrl(userProvidedUrl)) {
            throw new IllegalArgumentException("Invalid URL provided!");
        }

        URL url = new URL(userProvidedUrl);

        // Enforce the allowlist
        if (!isAllowedDomain(url)) {
            throw new SecurityException("The domain is not allowed!");
        }

        // Proceed with making a safe HTTP request
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        System.out.println("Response Code: " + responseCode);
        // Perform proper processing or error handling here
    }

    // Validate URL
    private static boolean isValidUrl(String url) {
        try {
            new URL(url);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    // Check if URL is within the allowlist
    private static boolean isAllowedDomain(URL url) {
        for (String allowedDomain : ALLOWED_DOMAINS) {
            if (url.toString().startsWith(allowedDomain)) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args) {
        try {
            // Example user input
            makeRequest("https://trusted.com/resource");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}