package tcp7;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class IPv6TunnelClientTCP {
    private static final int IPV4_HEADER_LENGTH = 20;
    private static final int IPV6_HEADER_LENGTH = 40;

    public static void main(String[] args) {
        String serverIPv4 = "0.0.0.0"; // Replace with actual server IPv4 address
        int serverPort = 9999;

        byte[][] qosSettings = {
            {5, 2, 1}, // Low latency, medium reliability
            {3, 3, 3}, // Balanced
            {1, 5, 2}  // High reliability, lower priority
        };

        String[] messages = {
            "Short message",
            "Moderately long message with more content",
            "Long message to test throughput and latency effects"
        };

        for (int i = 0; i < messages.length; i++) {
            String message = messages[i];
            byte[] qos = qosSettings[i % qosSettings.length];

            try {
                long startTime = System.nanoTime();

                byte[] ipv6Packet = createIPv6PacketWithQoSAndData(
                    message.getBytes(StandardCharsets.UTF_8),
                    qos[0], qos[1], qos[2],
                    InetAddress.getByName("2001:db8::1"),  // Source IPv6
                    InetAddress.getByName("2001:db8::2")   // Destination IPv6
                );

                byte[] ipv4Packet = createIPv4PacketWithEncapsulatedIPv6("192.0.2.1", serverIPv4, ipv6Packet);

                // Log QoS settings and packet size before sending
                System.out.println("Sending packet with message length: " + message.length() + " bytes");
                System.out.println("Custom QoS - Priority: " + qos[0] + ", Reliability: " + qos[1] + ", Latency: " + qos[2]);
                
                // Simulate the latency based on QoS and packet size
                long simulatedLatency = calculateLatencyBasedOnSize(message.length(), qos[2]);
                System.out.println("Simulating latency: " + simulatedLatency + " ms");

                // Add simulated delay
                Thread.sleep(simulatedLatency);

                sendPacketOverTCP(serverIPv4, serverPort, ipv4Packet);

                long endTime = System.nanoTime();
                long latency = (endTime - startTime) / 1_000_000;  // Convert to milliseconds
                System.out.println("Latency: " + latency + " ms for message size " + message.length() + " bytes.\n");

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Creates an IPv6 packet with custom QoS fields and the message payload
    private static byte[] createIPv6PacketWithQoSAndData(
            byte[] payloadData, byte priority, byte reliability, byte latency,
            InetAddress srcIPv6, InetAddress destIPv6) {

        ByteBuffer qosBuffer = ByteBuffer.allocate(3);
        qosBuffer.put(priority).put(reliability).put(latency);

        byte[] qosAndPayload = new byte[qosBuffer.capacity() + payloadData.length];
        System.arraycopy(qosBuffer.array(), 0, qosAndPayload, 0, qosBuffer.capacity());
        System.arraycopy(payloadData, 0, qosAndPayload, qosBuffer.capacity(), payloadData.length);

        ByteBuffer buffer = ByteBuffer.allocate(IPV6_HEADER_LENGTH + qosAndPayload.length);

        int versionTrafficClassFlowLabel = (6 << 28) | (0 << 20) | 12345;  // IPv6 version, traffic class, flow label
        buffer.putInt(versionTrafficClassFlowLabel);
        buffer.putShort((short) qosAndPayload.length);  // Payload length
        buffer.put((byte) 0); // Next header (zero indicates IPv6 header)
        buffer.put((byte) 64); // Hop limit (maximum hops for IPv6 packet)
        buffer.put(srcIPv6.getAddress());
        buffer.put(destIPv6.getAddress());
        buffer.put(qosAndPayload);

        return buffer.array();
    }

    // Encapsulates the IPv6 packet inside an IPv4 packet for transmission
    private static byte[] createIPv4PacketWithEncapsulatedIPv6(String srcIPv4, String destIPv4, byte[] ipv6Packet) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(IPV4_HEADER_LENGTH + ipv6Packet.length);
        buffer.put((byte) 0x45);  // IPv4 version and header length
        buffer.put((byte) 0);     // Type of Service
        buffer.putShort((short) (IPV4_HEADER_LENGTH + ipv6Packet.length));  // Total length
        buffer.putShort((short) 0);  // Identification
        buffer.putShort((short) 0);  // Flags + Fragment offset
        buffer.put((byte) 64);  // TTL
        buffer.put((byte) 41);  // Protocol (41 indicates IPv6 encapsulation)
        buffer.putShort((short) 0);  // Checksum (zero for simplicity)

        buffer.put(InetAddress.getByName(srcIPv4).getAddress());
        buffer.put(InetAddress.getByName(destIPv4).getAddress());
        buffer.put(ipv6Packet);

        return buffer.array();
    }

    // Sends the encapsulated IPv6 packet over TCP to the server
    private static void sendPacketOverTCP(String destIPv4, int port, byte[] packet) throws Exception {
        try (Socket socket = new Socket(destIPv4, port);
             OutputStream outputStream = socket.getOutputStream()) {
            outputStream.write(packet);
            outputStream.flush();
        }
    }

    // Function to calculate simulated latency based on the packet size and QoS latency field
    private static long calculateLatencyBasedOnSize(int messageSize, byte qosLatency) {
        // Base latency from QoS setting
        long latency = qosLatency * 2; // Each unit of latency increases by 2 ms

        // Add delay based on message size (simple formula, you can adjust as needed)
        if (messageSize < 50) {
            latency += 5; // Small packets (less than 50 bytes) add a small overhead
        } else if (messageSize < 100) {
            latency += 10; // Medium packets (50-100 bytes) add a medium overhead
        } else {
            latency += 15; // Larger packets (>100 bytes) add more overhead
        }

        return latency;
    }
}

