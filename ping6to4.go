package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
	"log"
	"math/rand"
	"net"
	"time"
)

type ICMPv6Echo struct {
	layers.ICMPv6Echo
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	my_ipv4_str := flag.String("my_ipv4", "", "your public ipv4 address (example \"192.0.2.0\")")
	ping_ipv6_str := flag.String("ping_ipv6", "", "ipv6 host to ping (example \"2001:db8::\")")
	tunnel_str := flag.String("tunnel", "192.88.99.1", "6to4 tunnel ipv4 address")

	flag.Parse()

	my_ipv4 := net.ParseIP(*my_ipv4_str).To4()

	if my_ipv4 == nil {
		fmt.Print("Set my_ipv4 option\n")
		flag.PrintDefaults()
		return
	}

	tunnel_ipv4 := net.ParseIP(*tunnel_str).To4()

	if tunnel_ipv4 == nil {
		fmt.Print("Set tunnel_ipv4 option\n")
		flag.PrintDefaults()
		return
	}

	ping_ipv6 := net.ParseIP(*ping_ipv6_str)

	if ping_ipv6 == nil {
		fmt.Print("Set ping_ipv6 option\n")
		flag.PrintDefaults()
		return
	}

	my_ipv6 := net.IP([]byte{0x20, 0x02, my_ipv4[0], my_ipv4[1], my_ipv4[2], my_ipv4[3], byte(rand.Intn(255)), byte(rand.Intn(255)), 0, 0, 0, 0, 0, 0, 0, 1})

	fmt.Printf("Ping from\n  IPv4: %v\n  IPv6: %v \nTo\n  IPv4(tunnel): %v\n  IPv6: %v\n", my_ipv4, my_ipv6, tunnel_ipv4, ping_ipv6)

	//go pingIPv4(tunnel_ipv4)
	//go pingIPv6(ping_ipv6)

	go waitIPv4ICMP()

	ping6to4(
		my_ipv6,
		ping_ipv6,
		tunnel_ipv4,
	)
}

func (icmpv6echo *ICMPv6Echo) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeICMPv6Echo
}

func ping6to4(srcIPv6 net.IP, dstIPv6 net.IP, tunnelIPv4 net.IP) {
	cc, err := net.ListenPacket("ip4:41", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer cc.Close()

	c := ipv4.NewPacketConn(cc)

	payload_layer := gopacket.Payload([]byte("abcdefghijklmnopqrstuvwabcdefghi"))

	ipv6_layer := &layers.IPv6{
		Version:    6,
		Length:     8 + uint16(len(payload_layer)),
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
		SrcIP:      srcIPv6,
		DstIP:      dstIPv6,
	}

	icmp_layer := &layers.ICMPv6{
		TypeCode: layers.ICMPv6TypeEchoRequest << 8, // Type: Echo request
	}

	seq := uint16(rand.Intn((1 << 16) - 1))

	echo_layer := &layers.ICMPv6Echo{
		Identifier: 1,
		SeqNumber:  seq,
	}

	icmp_layer.SetNetworkLayerForChecksum(ipv6_layer)

	buf := gopacket.NewSerializeBuffer()

	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true},
		ipv6_layer,
		icmp_layer,
		echo_layer,
		payload_layer,
	)

	packetData := buf.Bytes()

	respPacket := make([]byte, 65000)

	c.WriteTo(packetData, nil, &net.IPAddr{
		IP: tunnelIPv4,
	})

	fmt.Printf("6to4 send ping: %v (sender) -> %v (tunnel) -> %v (host)\n\n", srcIPv6, tunnelIPv4, dstIPv6)
	t := time.Now()
	c.SetReadDeadline(t.Add(10 * time.Second))
	n, _, src, err := c.ReadFrom(respPacket)
	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Printf("6to4 responce tunnel: %v\n", src)

		var ipv6 layers.IPv6
		var icmpv6 layers.ICMPv6
		var icmpv6echo ICMPv6Echo
		var reply bool
		var seqb bool

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ipv6, &icmpv6, &icmpv6echo)
		decoded := []gopacket.LayerType{}
		parser.DecodeLayers(respPacket[:n], &decoded)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv6:
				fmt.Printf("6to4 responce from: %s\n", ipv6.SrcIP)
				fmt.Printf("6to4 responce to: %s\n", ipv6.DstIP)
			case layers.LayerTypeICMPv6:
				reply = icmpv6.TypeCode >> 8 == layers.ICMPv6TypeEchoReply
				fmt.Printf("6to4 responce type: %s (%v)\n", icmpv6.TypeCode, reply)
			case layers.LayerTypeICMPv6Echo:
				seqb = icmpv6echo.SeqNumber == seq
				fmt.Printf("6to4 responce seq: %d (%v)\n\n", icmpv6echo.SeqNumber, seqb)
			}
		}
		if reply && seqb {
			fmt.Print("Ok")
		}
	}
}

func getPacketIPv4(seq uint16, packettype layers.ICMPv4TypeCode) []byte {
	payload_layer := gopacket.Payload([]byte("abcdefghijklmnopqrstuvwabcdefghi"))

	icmp_layer := &layers.ICMPv4{
		TypeCode: packettype << 8, // Type: Echo request
		Id:       1,
		Seq:      seq,
	}

	buf := gopacket.NewSerializeBuffer()

	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true},
		icmp_layer,
		payload_layer,
	)

	return buf.Bytes()
}

func waitIPv4ICMP() {
	cc, err := net.ListenPacket("ip4:icmp", "0.0.0.0")

	if err != nil {
		log.Fatal(err)
	}
	defer cc.Close()

	c := ipv4.NewPacketConn(cc)

	packet := make([]byte, 65000)
	n, _, src, err := c.ReadFrom(packet)
	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Printf("ipv4 responce from: %v\n", src)

		var icmpv4 layers.ICMPv4
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv4, &icmpv4)
		decoded := []gopacket.LayerType{}
		parser.DecodeLayers(packet[:n], &decoded)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeICMPv4:
				fmt.Printf("ipv4 responce type: %s\n", icmpv4.TypeCode)
				fmt.Printf("ipv4 responce seq: %d \n\n", icmpv4.Seq)
			}
		}
	}
}

func pingIPv4(dstIPv4 net.IP) {
	cc, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}
	defer cc.Close()

	c := ipv4.NewPacketConn(cc)

	seq := uint16(rand.Intn((1 << 16) - 1))
	reqPacket := getPacketIPv4(seq, layers.ICMPv4TypeEchoRequest)
	packet := make([]byte, 65000)

	c.WriteTo(reqPacket, nil, &net.IPAddr{
		IP: dstIPv4,
	})

	fmt.Printf("ipv4 send ping to: %v\n\n", dstIPv4)

	n, _, src, err := c.ReadFrom(packet)
	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Printf("ipv4 responce from: %v\n", src)

		var icmpv4 layers.ICMPv4
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv4, &icmpv4)
		decoded := []gopacket.LayerType{}
		parser.DecodeLayers(packet[:n], &decoded)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeICMPv4:
				fmt.Printf("ipv4 responce type: %s (%v)\n", icmpv4.TypeCode, icmpv4.TypeCode >> 8 == layers.ICMPv4TypeEchoReply)
				fmt.Printf("ipv4 responce seq: %d (%v)\n\n", icmpv4.Seq, icmpv4.Seq == seq)
			}
		}
	}
}

func pingIPv6(dstIPv6 net.IP) {
	cc, err := net.ListenPacket("ip6:58", "::")
	if err != nil {
		log.Fatal(err)
	}
	defer cc.Close()

	c := ipv4.NewPacketConn(cc)

	//c.SetTTL(255)

	payload_layer := gopacket.Payload([]byte("abcdefghijklmnopqrstuvwabcdefghi"))

	icmp_layer := &layers.ICMPv6{
		TypeCode: layers.ICMPv6TypeEchoRequest << 8, // Type: Echo request
	}

	seq := uint16(rand.Intn((1 << 16) - 1))

	echo_layer := &layers.ICMPv6Echo{
		Identifier: 1,
		SeqNumber:  seq,
	}

	buf := gopacket.NewSerializeBuffer()

	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true},
		icmp_layer,
		echo_layer,
		payload_layer,
	)

	reqPacket := buf.Bytes()
	respPacket := make([]byte, 65000)

	c.WriteTo(reqPacket, nil, &net.IPAddr{
		IP: dstIPv6,
	})

	fmt.Printf("ipv6 send ping to: %v\n\n", dstIPv6)
	n, _, src, err := c.ReadFrom(respPacket)
	if err != nil {
		fmt.Print(err)
	} else {

		fmt.Printf("ipv4 responce from: %v\n", src)

		var icmpv6 layers.ICMPv6
		var icmpv6echo ICMPv6Echo
		var payload gopacket.Payload

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeICMPv6, &icmpv6, &icmpv6echo, &payload)
		decoded := []gopacket.LayerType{}
		parser.DecodeLayers(respPacket[:n], &decoded)
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeICMPv6:
				fmt.Printf("ipv6 responce type: %s (%v)\n", icmpv6.TypeCode, icmpv6.TypeCode >> 8 == layers.ICMPv6TypeEchoReply)
			case layers.LayerTypeICMPv6Echo:
				fmt.Printf("ipv6 responce seq: %d (%v)\n", icmpv6echo.SeqNumber, icmpv6echo.SeqNumber == seq)
			case gopacket.LayerTypePayload:
				fmt.Printf("ipv6 responce payload: %s\n", payload)
			}
		}
	}
}
