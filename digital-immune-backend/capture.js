const pcap = require('pcap');

// List available devices
const devices = pcap.findalldevs();
console.log('Available devices:', devices.map(d => d.name));

// Choose your network interface (e.g., 'eth0' or 'en0')
const device = 'e0'; // Change to your interface name

// Create a pcap session to capture all packets
const pcapSession = pcap.createSession(device, {
  filter: 'ip', // capture only IP packets (optional)
});

console.log(`Listening on ${device}...`);

pcapSession.on('packet', rawPacket => {
  const packet = pcap.decode.packet(rawPacket);
  try {
    const ip = packet.payload.payload; // IPv4 layer
    const srcIP = ip.saddr.addr.join('.');
    const dstIP = ip.daddr.addr.join('.');
    const protocol = ip.protocol_name;

    console.log(`Packet: ${srcIP} -> ${dstIP} [${protocol}]`);
    // TODO: Pass packet info to threat detection logic
  } catch (err) {
    // Ignore malformed packets
  }
}); 