package net_sniff

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/biero-el-corridor/Bettercap_ICS/packets"

	"github.com/evilsocket/islazy/tui"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"golang.org/x/text/cases"
	// get custom packet from the packet sections of bettercap
)

<<<<<<< HEAD
=======
///////////////////////////////////////////////////
// start of the packet/modbus.go sections /////////
///////////////////////////////////////////////////

// Following code based on this website : https://ozeki.hu/p_5873-modbus-function-codes.html
const (
	// VALUE REPRESENTED AS DECIMAL
	// VALUE OF THE FUNCTIONS CODE
	READ_COILS                       = 1
	READ_DISCRETE_INPUTS             = 2
	READ_MULTIPLE_HOLDING_REGISTERS  = 3
	READ_INPUT_REGISTERS             = 4
	WRITE_SINGLE_COIL                = 5
	WRITE_SINGLE_HOLDING_REGISTER    = 6
	READ_EXCEPTION_STATUS            = 7
	DIAGNOSTIC                       = 8
	GET_COM_EVENT_COUNTER            = 11
	GET_COM_EVENT_LOG                = 12
	WRITE_MULTIPLE_COILS             = 15
	WRITE_MULTIPLE_HOLDING_REGISTERS = 16
	REPORT_SLAVE_ID                  = 17
	READ_FILE_RECORD                 = 20
	WRITE_FILE_RECORD                = 21
	MASK_WRITE_REGISTER              = 22
	READ_WRITE_MULTIPLE_REGISTERS    = 23
	READ_FIFO_QUEUE                  = 24
	READ_DEVICE_IDENTIFICATION       = 43
	ENCAPSULATED_INTERFACE_TRANSPORT = 43

	//exeptions (error handeling) code for the modbus functions code
	READ_COIL_EXEPTION           = 129 // exeptions error code for the read coil functions code
	READ_DISCRETE_INPUTS_EXEPION = 130
)

>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
// Declare global
var list = &List{}
var a = 0

<<<<<<< HEAD
=======
type ModbusTCP_struct struct {
	TID    uint16 `json:"TID"`
	PID    uint16 `json:"PID"`
	Lenght uint16 `json:"Lenght"`
	UID    uint8  `json:"UID"`
}

// //////////////////////
// Funtions code 1 & 2 query and reply
type Modbus_FUNCTIONS_CODE_1_OR_2_query struct {
	FUNCTION_CODE    uint8  `json:"FUNCTION_CODE"`
	REFERENCE_NUMBER uint16 `json:"REFERENCE_NUMBER"`
	BITE_COUNT       uint16 `json:"BITE_COUNT"`
}

type Modbus_FUNCTIONS_CODE_1_OR_2_reply struct {
	FUNCTION_CODE uint8           `json:"FUNCTION_CODE"`
	BITE_COUNT    uint8           `json:"BITE_COUNT"`
	DATA          map[uint16]byte `json:"WORD_COUNT"`
}

// //////////////////////
// Funtions code 3 & 4
type Modbus_FUNCTIONS_CODE_3_OR_4_query struct {
	FUNCTION_CODE    uint8  `json:"FUNCTION_CODE"`
	REFERENCE_NUMBER uint16 `json:"REFERENCE_NUMBER"`
	WORD_COUNT       uint16 `json:"WORD_COUNT"`
}

type Modbus_FUNCTIONS_CODE_3_OR_4_reply struct {
	FUNCTION_CODE uint8             `json:"FUNCTION_CODE"`
	BYTE_COUNT    uint16            `json:"BITE_COUNT"`
	DATA          map[uint16]uint16 `json:"WORD_COUNT"`
}

// //////////////////////
// Funtions code 5 & 6
// The two funtions have the same query structure.
// SO there why there is no reply structure
type Modbus_FUNCTIONS_CODE_5_OR_6_query struct {
	FUNCTION_CODE    uint8  `json:"FUNCTION_CODE"`
	REFERENCE_NUMBER uint16 `json:"REFERENCE_NUMBER"`
	DATA             uint16 `json:"DATA"`
}

type Modbus_FUNCTIONS_CODE_15_query struct {
	FUNCTION_CODE    uint8  `json:"FUNCTION_CODE"`
	REFERENCE_NUMBER uint16 `json:"REFERENCE_NUMBER"`
	BIT_COUNT        uint16 `json:"BIT_COUNT"`
	BYTE_COUNT       uint8  `json:"BYTE_COUNT"`
	DATA             []byte `json:"DATA"`
}

type Modbus_FUNCTIONS_CODE_16_query struct {
	FUNCTION_CODE    uint8  `json:"FUNCTION_CODE"`
	REFERENCE_NUMBER uint16 `json:"REFERENCE_NUMBER"`
	WORD_COUNT       uint16 `json:"WORD_COUNT"`
	BYTE_COUNT       uint8  `json:"BYTE_COUNT"`
	DATA             []byte `json:"DATA"`
}

////////////////////////

// //////////////////////
// Conversion functions
// //////////////////////

func byte_decimal_array_to_decimal_uint8(array []byte) uint8 {
	//	because I get decimal value in each array
	//	I need to convert to hex concat and then convert to decimal.
	byteArray := array
	hexadecimal_num := hex.EncodeToString(byteArray)
	fmt.Println("Encoded Hex String: ", hexadecimal_num)
	// use the parseInt() function to convert
	decimal_num, err := strconv.ParseInt(hexadecimal_num, 16, 64)
	decimal_value := uint8(decimal_num)

	// in case of any error
	if err != nil {
		panic(err)
	}
	return decimal_value
}

>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
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

<<<<<<< HEAD
=======
func VIEW_FUNCTIONS_CODE_1_OR_2(query []byte, reply []byte) (Modbus_FUNCTIONS_CODE_1_OR_2_query, Modbus_FUNCTIONS_CODE_1_OR_2_reply) {
	ModbusTCP_currentPacket_query := Modbus_FUNCTIONS_CODE_1_OR_2_query{
		FUNCTION_CODE:    uint8(query[0]),
		REFERENCE_NUMBER: byte_decimal_array_to_decimal_uint16(query[1:3]),
		//strconv.FormatUint(decimal, 16)
		BITE_COUNT: byte_decimal_array_to_decimal_uint16(query[3:5]),
	}

	count := 0
	DATA := reply[2:]
	parsed_data := map[uint16]byte{}
	BITE_COUNT := byte_decimal_array_to_decimal_uint16(query[3:5])
	REFERENCE_NUMBER := byte_decimal_array_to_decimal_uint16(query[1:3])
	for uint16(count) < BITE_COUNT {
		num := DATA[count]
		for i := 0; i <= 7; i++ { 
			// Iterate from MSB to LSB
			//fmt.Print("value of byte ", i, ": ")
			//fmt.Printf("%d \n", (num>>i)&1)
			coil_number := i + int(REFERENCE_NUMBER)
			value := (num >> i) & 1
			parsed_data[uint16(coil_number)] = value
			//fmt.Println("coil number :", coil_number, " || Value:", value)
			count++
		}
	}

	ModbusTCP_currentPacket_reply := Modbus_FUNCTIONS_CODE_1_OR_2_reply{
		FUNCTION_CODE: uint8(reply[0]),
		BITE_COUNT:    uint8(reply[1]),
		DATA:          parsed_data,
	}
	// extract the value of each coil
	// Counter for the number of byte to threat

	return ModbusTCP_currentPacket_query, ModbusTCP_currentPacket_reply
}

func VIEW_FUNCTIONS_CODE_3_OR_4(query []byte, reply []byte) (Modbus_FUNCTIONS_CODE_3_OR_4_query, Modbus_FUNCTIONS_CODE_3_OR_4_reply) {
	//	parsed_data map[uint16]uint16
	// 	structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket_query := Modbus_FUNCTIONS_CODE_3_OR_4_query{
		FUNCTION_CODE:    uint8(query[0]),
		REFERENCE_NUMBER: byte_decimal_array_to_decimal_uint16(query[1:3]),
		WORD_COUNT:       byte_decimal_array_to_decimal_uint16(query[3:5]),
	}
	// try to make the data parsing here instead of the print area
	// TODO:
	// - a new type to return that will represent the parsed data
	// ISSUE: 
	// - Only display half of the register , and output them in the wrong order
	DATA := reply[2:]
	count := 0
	count_data := 0
	count_register := 0
	word_count := byte_decimal_array_to_decimal_uint16(query[3:5])
	parsed_data := map[uint16]uint16{}
	fmt.Println("value of wordcount", word_count)
	start_reference_number := byte_decimal_array_to_decimal_uint16(query[1:3])
	for count < int(word_count) {
		register_number := int(start_reference_number) + count_register
		value := byte_decimal_array_to_decimal_uint16(DATA[count_data : count_data+2])
		parsed_data[uint16(register_number)] = value
		//fmt.Println("register number :", register_number, " || Value:", value)
		count_register++
		count++
		count_data++
		count_data++
	}

	ModbusTCP_currentPacket_reply := Modbus_FUNCTIONS_CODE_3_OR_4_reply{
		FUNCTION_CODE: uint8(reply[0]),
		BYTE_COUNT:    byte_decimal_array_to_decimal_uint16(reply[1:2]),
		DATA:          parsed_data,
	}

	//fmt.Println("after test")
	return ModbusTCP_currentPacket_query, ModbusTCP_currentPacket_reply
}

func VIEW_FUNCTIONS_CODE_5_OR_6(modbus []byte) Modbus_FUNCTIONS_CODE_5_OR_6_query {
	// structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket := Modbus_FUNCTIONS_CODE_5_OR_6_query{
		FUNCTION_CODE:    uint8(modbus[0]),
		REFERENCE_NUMBER: byte_decimal_array_to_decimal_uint16(modbus[1:3]),
		// Wireshark represents it in heaxdecimal , I choose to represent it in decimal
		DATA: byte_decimal_array_to_decimal_uint16(modbus[3:5]),
	}
	return ModbusTCP_currentPacket
}

func VIEW_FUNCTIONS_CODE_15(modbus []byte) Modbus_FUNCTIONS_CODE_15_query {
	// structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket := Modbus_FUNCTIONS_CODE_15_query{
		FUNCTION_CODE:    uint8(modbus[0]),
		REFERENCE_NUMBER: uint16(modbus[1])*100 + uint16(modbus[2]),
		BIT_COUNT:        uint16(modbus[3])*100 + uint16(modbus[4]),
		BYTE_COUNT:       uint8(modbus[5]),
		DATA:             []byte(modbus[6:]),
	}
	return ModbusTCP_currentPacket
}

///////////////////////////////////////////////////
// end of the packet/modbus.go sections ///////////
///////////////////////////////////////////////////

>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
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
	src_port    string
	tcp_payload []byte
	next        *Node
}

<<<<<<< HEAD
// Chain definition
=======
//	Chain definition 
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
type List struct {
	head *Node
}

<<<<<<< HEAD
// Add node to chain
=======
//	Add node to chain
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
func (l *List) add(value string, TCP_payload []byte) {
	newNode := &Node{src_port: value, tcp_payload: TCP_payload}
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

<<<<<<< HEAD
// Delete node from chain
=======
//	Delete node from chain
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
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
func get_stored_query(l *List, val string) []byte {
	curr := l.head
	var tcp_p []byte

	//	Note that the query cannot be analyze in the loop if it is empty
	if val == "" {
<<<<<<< HEAD
		fmt.Println("empty line found")
		return nil
	}
=======
		fmt.Println("Empty query provided")
        return nil
    }
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066

	for curr != nil {
		//fmt.Println("value of the port in the linked list", curr.src_port)
		if curr.src_port == val {
			tcp_p = curr.tcp_payload
			//fmt.Println("\n value to exprot and delet")
			//fmt.Println("\n src port ", curr.src_port)
			//fmt.Println("tcp payload", curr.tcp_payload)
			return tcp_p
		}
		curr = curr.next
	}
	return tcp_p
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

<<<<<<< HEAD
// Add Source / Destination ports
=======
//	Add Source / Destination ports
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
func modbusTcpParser(srcIP, dstIP net.IP, payload []byte, pkt gopacket.Packet, tcp *layers.TCP) bool {

	// define the list for the linked list
	//list := &List{}
	//var Is_query = false
	//var Is_reply = false
<<<<<<< HEAD
=======

>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
	modbus := pkt.TransportLayer().LayerPayload()
	transportlayer := pkt.TransportLayer()
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
		list.add(srcPORT[0:5], modbus)

	}
	//	Reply
	if strings.Contains(srcPORT[0:4], "502(") && ModbusTCP_currentPacket.PID == uint16(0) {
		//Is_reply = true
		//Is_query = false
		query_payload := get_stored_query(list, dstPORT[0:5])
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
<<<<<<< HEAD
					read_coil, reply := packets.VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
=======
					read_coil, reply := VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
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
					fmt.Println("	Functions code = ", read_coil.FUNCTION_CODE, " READ_COIL")
					fmt.Println("	Reference Number = ", read_coil.REFERENCE_NUMBER)
					fmt.Println("	Bit count = ", read_coil.BITE_COUNT)
					fmt.Println("/////")
					fmt.Println(" Modbus reply")
					fmt.Println("	Functions code = ", reply.FUNCTION_CODE)
					// print the value of the data byte value
					// counter for the number of byte to do
					for key, value := range reply.DATA {
						fmt.Println("coil number :", key, " || Value:", value)
					}
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
<<<<<<< HEAD
					read_discrete_input, reply := packets.VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
=======
					read_discrete_input, reply := VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
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
					fmt.Println("	Functions code = ", read_discrete_input.FUNCTION_CODE, " READ_COIL")
					fmt.Println("	Reference Number = ", read_discrete_input.REFERENCE_NUMBER)
					fmt.Println("	Bit count = ", read_discrete_input.BITE_COUNT)
					fmt.Println("/////")
					fmt.Println(" Modbus reply")
					fmt.Println("	Functions code = ", reply.FUNCTION_CODE)

					// print the value of the data byte value
					// counter for the number of byte to analyze
					for key, value := range reply.DATA {
						fmt.Println("coil number :", key, " || Value:", value)
					}
				} else {
					fmt.Println("Exeption code: Illegal data address")
				}
				//fmt.Println("data requested : ", modbus[9:])
			// functions code 3 , same concept as the read coil , but with register instead of coil.
			case packets.READ_MULTIPLE_HOLDING_REGISTERS:
				//fmt.Println("read multiple haloding register entering functions")
<<<<<<< HEAD
				query, reply := packets.VIEW_FUNCTIONS_CODE_3_OR_4(query_payload[7:], modbus[7:])
=======
				query, reply := VIEW_FUNCTIONS_CODE_3_OR_4(query_payload[7:], modbus[7:])
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066

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
<<<<<<< HEAD

=======
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
				// print the uint16 register
				for key, value := range reply.DATA {
					fmt.Println("register number :", key, " || Value:", value)
				}

<<<<<<< HEAD
			case packets.READ_INPUT_REGISTERS:
				query, reply := packets.VIEW_FUNCTIONS_CODE_3_OR_4(query_payload[7:], modbus[7:])
=======
			case READ_INPUT_REGISTERS:
				query, reply := VIEW_FUNCTIONS_CODE_3_OR_4(query_payload[7:], modbus[7:])
>>>>>>> 709add8f2065d37023659ce90dfbb4247656e066
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
