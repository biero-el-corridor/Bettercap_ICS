package icmp_echo8

import (
	"crypto/rand"
	"encoding/hex"

	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	// session contain the sniffed interface parameter name

	"github.com/biero-el-corridor/Bettercap_ICS/session"
)

var (
	//device       string session.I.Interface.Hostname
	snapshot_len int32 = 1024
	promiscuous  bool  = true
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func exil_icmp_echo() {

	//session.I.Interface.Hostname
	device := session.I.Interface.Hostname
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ethernetLayer := &layers.Ethernet{ // https://pkg.go.dev/github.com/google/gopacket@v1.1.19/layers#Ethernet.EthernetType
		SrcMAC:       net.HardwareAddr{0x4C, 0xE7, 0x05, 0x10, 0x22, 0xA3},
		DstMAC:       net.HardwareAddr{0x4C, 0xE7, 0x05, 0x10, 0x22, 0xA3},
		EthernetType: 0x0800,
	}

	ipLayer := &layers.IPv4{ // https://pkg.go.dev/github.com/google/gopacket@v1.1.19/layers#IPv4
		Version:  4,
		IHL:      uint8(5),
		TOS:      0,
		Length:   40,
		Id:       28829,
		Flags:    2,
		Protocol: layers.IPProtocolICMPv4,
		TTL:      64,
		Checksum: 0,
		SrcIP:    net.IP{10, 0, 2, 15},
		DstIP:    net.IP{8, 8, 8, 8},
	}

	//note the icmp packet is not the same on windows and linux
	// the linux ICMP have a timestamp the windows does not
	icmpLayer := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(uint8(8), uint8(0)),
		Seq:      1, // avoir un roulement au niveaux de l'indicateur.
		Id:       3177,
	}

	////////////////////////
	///// TCP Sections
	///////////////////////
	//buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	////////////////////////
	///// ICMP Sections
	///////////////////////
	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer,
		options,
		ethernetLayer,
		ipLayer,
		icmpLayer,
		gopacket.Payload([]byte{1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 2, 3, 4, 5, 6}),
	)
	///////////////////
	/// packet sending
	///////////////////

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}
}
