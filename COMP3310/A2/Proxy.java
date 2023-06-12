import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.sql.Timestamp;
import java.util.HashMap;

public class Proxy {

    static String DOMAIN;
    static int PORT;
    static HashMap<String, String> cityMap;

    public static void main(String[] args) throws IOException {

        //read in arguments and assign argument 1 as the domain and argument 2 as the port
        //if no argument are assigned, assume the domain is bom.gov.au, and the port is 80.
        if (args.length == 2) {
            DOMAIN = args[0];
            PORT = Integer.valueOf(args[1]);
        } else {
            DOMAIN = "www.bom.gov.au";
            PORT = 80;
        }

        //create map of old city names to new city names
        cityMap = new HashMap<String, String>();
        populateMap();

        System.out.println("Proxy running for: " + DOMAIN + " on port: " + PORT);

        //run the server
        while (true) {
            serverTCP(PORT);
        }
    }

    public static void serverTCP(int port) throws IOException {

        //open sever socket on a port
        ServerSocket sSock = new ServerSocket(port);

        //wait for connection
        Socket sock = sSock.accept();

        //buffers for IO - outputting and reading in messages
        PrintStream out = new PrintStream(sock.getOutputStream());
        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
        StringBuilder inB = new StringBuilder();

        String line = in.readLine();

        //read in from in buffer and store it in inB which is then converted to a string and stored in the variable inMsg. This is the query.
        while (line != null && !line.equals("")) {
            inB.append(line + "\r\n");
            line = in.readLine();
        }

        String inMsg = inB.toString();

        //if the message is not empty process it.
        if (inMsg != null && !inMsg.equals("")) {

            //output timestamp of when the server recieved the message with the request time
            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
            System.out.println(timestamp);
            System.out.println("Request: " + inMsg.split("\n", 2)[0]);


            //Retrieve what kind of file is trying to be retrieved, i.e. HTML, JGP etc...
            String link = inMsg.split("GET", 2)[1].split("HTTP", 2)[0].split("\\?", 2)[0].trim();

            //based on file type, obtain the resource and add it to the output buffer to be sent back to the client
            if (link.charAt(link.length() - 1) == '/' || link.substring(link.length() - 4).equals("html")) {
                out.print(getHTML(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 3).equals("php")) {
                out.print(getHTML(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 3).equals("css")) {
                out.print(getHTML(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 2).equals("js")) {
                out.print(getHTML(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 3).equals("png")) {
                out.write(getIMG(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 3).equals("ico")) {
                out.write(getIMG(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 3).equals("gif")) {
                out.write(getIMG(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 3).equals("jpg")) {
                out.write(getIMG(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 3).equals("svg")) {
                out.write(getIMG(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 4).equals("json")) {
                out.write(getOTHER(inMsg, DOMAIN));
            } else if (link.substring(link.length() - 3).equals("cgi")) {
                out.write(getOTHER(inMsg, DOMAIN));
            } else {
                try {
                    out.write(getOTHER(inMsg, DOMAIN));
                } catch (Exception e){}
            }
        }
        //printing to the command line formatting
        System.out.println();

        //close the server, (server reopened by the loop in main).
        in.close();
        out.close();
        sock.close();
        sSock.close();
    }

    public static String getHTML(String query, String host) throws IOException {

        //extract link from the query i.e. GET X HTTP/1.0... Becomes X.
        String page = query.split("GET", 2)[1].split("HTTP", 2)[0].split("\\?", 2)[0].trim();

        //revert the changes in the link from when they where modified when the HTML was retrieved to ensure that pages still work.
        //i.e. if Sydney is changed to Computer, this line makes DOMAIN/Computer redirect to DOMAIN/Sydney
        page = undoChangeCity(page);

        //build basic query
        StringBuilder message = new StringBuilder();
        message.append("GET " + page + " HTTP/1.0").append("\r\n");
        message.append("Host: " + host).append("\r\n");
        message.append("User-Agent: Ultraseek").append("\r\n");
        message.append("Connection: close").append("\r\n").append("\r\n");

        //open a TCP connection to the DOMAIN, usually www.bom.gov.au and retrieve the data from the above query
        byte[] data = clientTCP( host, 80, message.toString());

        //convert byte data to string i.e. Headers + HTML
        String str = new String(data);

        //split response into headers and content
        String headers = str.split("\n\r", 2)[0];
        String body = str.split("\n\r", 2)[1];

        //change the cities to other city names (changes both text AND LINKS, but link changes are undone when they're clicked) - prints number of changes from within the function
        body = changeCity(body);

        //https://stackoverflow.com/questions/767759/occurrences-of-substring-in-a-string#answer-44838176
        //code inspiration taken from this stackoverflow answer, counts number of occurrences of a substring (<a href"domain).
        //counts occurances of target string before they are changed by String.replaceFirst.
        int count = 0;
        count += (str.length() - str.replace("href=\"http://" + DOMAIN, "").length()) / ("href=\"http://" + DOMAIN).length();
        count += (str.length() - str.replace("href=\"" + DOMAIN, "").length()) / ("href=\"" + DOMAIN).length();

        //reroute all links to go via proxy
        //replace href="www.bom.gov.au/X> with href="/X>
        body = body.replaceAll("href=\"http://" + DOMAIN, "href=\"");
        body = body.replaceAll("href=\"" + DOMAIN, "href=\"");
        System.out.println("Link changes: " + count);

        //combine headers and body back to send to the client with a new line carriage return (\n\r was removed when we split the string).
        return headers + "\n\r" + body;
    }

    public static byte[] getIMG(String query, String host) throws IOException {

        //extract link from the query i,e, from GET X HTTP/1.0... Becomes X.
        String page = query.split("GET", 2)[1].split("HTTP", 2)[0].split("\\?", 2)[0].trim();

        //build up a basic query
        StringBuilder message = new StringBuilder();
        message.append("GET " + page + " HTTP/1.0").append("\r\n");
        message.append("Host: " + host).append("\r\n");
        message.append("User-Agent: Ultraseek").append("\r\n");
        message.append("Connection: close").append("\r\n");
        message.append("\r\n");

        //open a TCP connection to the DOMAIN, usually www.bom.gov.au and retrieve the data from the query built above
        byte[] data = clientTCP(host, 80, message.toString());

        //have the potential to modify the image here (will need to extract headers and such

        //return the bytes
        return data;
    }

    public static byte[] getOTHER(String query, String host) throws IOException {

        //extract link from the query i,e, from GET X HTTP/1.0... Becomes X.
        String page = query.split("GET", 2)[1].split("HTTP", 2)[0].split("\\?", 2)[0].trim();

        //build up a basic query
        StringBuilder message = new StringBuilder();
        message.append("GET " + page + " HTTP/1.0").append("\r\n");
        message.append("Host: www." + host).append("\r\n");
        message.append("User-Agent: Ultraseek").append("\r\n");
        message.append("Connection: close").append("\r\n");
        message.append("\r\n");

        //open a TCP connection to the DOMAIN, usually www.bom.gov.au and retrieve the data
        byte[] data = clientTCP(host, 80, message.toString());

        //return the bytes
        return data;
    }

    public static byte[] clientTCP(String URL, int port, String message) throws IOException {

        //resolve hostname - i.e. convert from www.bom.gov.au to an IP
        InetAddress address = InetAddress.getByName(URL);

        //create socket and out buffer
        Socket sock = new Socket(address, port);
        PrintStream out = new PrintStream(sock.getOutputStream());

        //sending message
        out.print(message);

        //get result from the server and store it as an array of bytes - done like this so we can use the same code to get HTML/IMG/JS/Etc...
        byte[] in = (sock.getInputStream()).readAllBytes();

        System.out.println("Response status: HTTP" + new String(in).split("HTTP",2)[1].split("\n",2)[0]);

        //close sockets and buffers
        sock.getInputStream().close();
        out.close();
        sock.close();

        return in;
    }

    public static void populateMap() {
        //arbitrary mapping between old city names and new city names
        cityMap.put("Sydney", "Sydnepore");
        cityMap.put("sydney", "sydnepore");
        cityMap.put("Canberra", "Canberrapore");
        cityMap.put("canberra", "canberrapore");
        cityMap.put("Melbourne", "Melbapore");
        cityMap.put("melbourne", "melbapore");
        cityMap.put("Hobart", "Hobapore");
        cityMap.put("hobart", "hobapore");
        cityMap.put("Adelaide", "Adepore");
        cityMap.put("adelaide", "adepore");
        cityMap.put("Brisbane", "Brisbapore");
        cityMap.put("brisbane", "brisbapore");
        cityMap.put("Darwin", "Charles");
        cityMap.put("darwin", "charles");
        cityMap.put("Perth", "Perthapore");
        cityMap.put("perth", "perthapore");
    }

    public static String changeCity(String str) {
        //count number of changes
        int count = 0;
        //cityMap is a map between city names that could occur in the article and their new names. Loop through all the keys (old city names), and replace the keys(old city names) with the values(new city names) from the map in the article.
        for (String key : cityMap.keySet()) {
            //https://stackoverflow.com/questions/767759/occurrences-of-substring-in-a-string#answer-44838176
            count += (str.length() - str.replace(key, "").length()) / key.length();
            str = str.replaceAll(key, cityMap.get(key));
        }
        System.out.print("Text changes: " + count + " ");
        return str;
    }

    public static String undoChangeCity(String str) {
        //cityMap is a map between city names that could occur in the article and their new names. Loop through all the keys(old city names, and replace the values(new names) from the map with the keys(old names) in the article.
        for (String key : cityMap.keySet()) {
            str = str.replaceAll(cityMap.get(key), key);
        }
        return str;
    }
}