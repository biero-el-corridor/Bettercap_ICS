package net_sniff

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/evilsocket/islazy/tui"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"golang.org/x/text/cases"
	// get custom packet from the packet sections of bettercap
)

///////////////////////////////////////////////////
// start of the packet/modbus.go sections /////////
///////////////////////////////////////////////////

// reference dissector from the wireshark project
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

// devcalre global variable
var list = &List{}
var a = 0

type ModbusTCP_struct struct {
	TID    uint16 `json:"TID"`
	PID    uint16 `json:"PID"`
	Lenght uint16 `json:"Lenght"`
	UID    uint8  `json:"UID"`
}

// //////////////////////
// Funtions code 1 & 2 query and responce
type Modbus_FUNCTIONS_CODE_1_OR_2_query struct {
	FUNCTION_CODE    uint8  `json:"FUNCTION_CODE"`
	REFERENCE_NUMBER uint16 `json:"REFERENCE_NUMBER"`
	BITE_COUNT       uint16 `json:"BITE_COUNT"`
}

type Modbus_FUNCTIONS_CODE_1_OR_2_responce struct {
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

type Modbus_FUNCTIONS_CODE_3_OR_4_responce struct {
	FUNCTION_CODE uint8             `json:"FUNCTION_CODE"`
	BYTE_COUNT    uint16            `json:"BITE_COUNT"`
	DATA          map[uint16]uint16 `json:"WORD_COUNT"`
}

// //////////////////////
// Funtions code 5 & 6
// The two funtions have the same query structure.
// SO there why there is no responce structure
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
// convertions sections
// //////////////////////

func byte_decimal_array_to_decimal_uint8(array []byte) uint8 {
	//because i ger decimal value in eatch array
	//i need to convert to hex concat and then convert to decimal , and i have the value.
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

func byte_decimal_array_to_decimal_uint16(array []byte) uint16 {

	//because i ger decimal value in eatch array
	//i need to convert to hex concat and then convert to decimal , and i have the value.
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
func viewModbusTCPEvent(modbus []byte) ModbusTCP_struct {
	// structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket := ModbusTCP_struct{
		TID:    byte_decimal_array_to_decimal_uint16(modbus[0:2]),
		Lenght: uint16(modbus[4])*1000 + uint16(modbus[5]),
		UID:    uint8(modbus[6]),
	}
	return ModbusTCP_currentPacket
}

func VIEW_FUNCTIONS_CODE_1_OR_2(query []byte, responce []byte) (Modbus_FUNCTIONS_CODE_1_OR_2_query, Modbus_FUNCTIONS_CODE_1_OR_2_responce) {

	ModbusTCP_currentPacket_query := Modbus_FUNCTIONS_CODE_1_OR_2_query{
		FUNCTION_CODE:    uint8(query[0]),
		REFERENCE_NUMBER: byte_decimal_array_to_decimal_uint16(query[1:3]),
		//strconv.FormatUint(decimal, 16)
		BITE_COUNT: byte_decimal_array_to_decimal_uint16(query[3:5]),
	}

	count := 0
	DATA := responce[2:]
	parsed_data := map[uint16]byte{}
	BITE_COUNT := byte_decimal_array_to_decimal_uint16(query[3:5])
	REFERENCE_NUMBER := byte_decimal_array_to_decimal_uint16(query[1:3])
	for uint16(count) < BITE_COUNT {
		num := DATA[count]
		for i := 0; i <= 7; i++ { // Iterate from MSB to LSB
			//fmt.Print("		value of byte ", i, ": ")
			//fmt.Printf("%d \n", (num>>i)&1)
			coil_number := i + int(REFERENCE_NUMBER)
			value := (num >> i) & 1
			parsed_data[uint16(coil_number)] = value
			//fmt.Println("coil number :", coil_number, " || Value:", value)
			count++
		}
	}

	ModbusTCP_currentPacket_responce := Modbus_FUNCTIONS_CODE_1_OR_2_responce{
		FUNCTION_CODE: uint8(responce[0]),
		BITE_COUNT:    uint8(responce[1]),
		DATA:          parsed_data,
	}
	// extract the value of eatch coil
	// counter for the number of byte to do

	return ModbusTCP_currentPacket_query, ModbusTCP_currentPacket_responce
}

func VIEW_FUNCTIONS_CODE_3_OR_4(query []byte, responce []byte) (Modbus_FUNCTIONS_CODE_3_OR_4_query, Modbus_FUNCTIONS_CODE_3_OR_4_responce) {
	//parsed_data map[uint16]uint16
	// structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket_query := Modbus_FUNCTIONS_CODE_3_OR_4_query{
		FUNCTION_CODE:    uint8(query[0]),
		REFERENCE_NUMBER: byte_decimal_array_to_decimal_uint16(query[1:3]),
		WORD_COUNT:       byte_decimal_array_to_decimal_uint16(query[3:5]),
	}
	// try to make the data parsing herer instead of the print area
	// ta add
	// - a new type to return that will represent the parsed data
	// ISSUE: inly display alf of the register , and output then in the wrong order
	DATA := responce[2:]
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
	ModbusTCP_currentPacket_responce := Modbus_FUNCTIONS_CODE_3_OR_4_responce{
		FUNCTION_CODE: uint8(responce[0]),
		BYTE_COUNT:    byte_decimal_array_to_decimal_uint16(responce[1:2]),
		DATA:          parsed_data,
	}

	//fmt.Println("after test")
	return ModbusTCP_currentPacket_query, ModbusTCP_currentPacket_responce
}

func VIEW_FUNCTIONS_CODE_5_OR_6(modbus []byte) Modbus_FUNCTIONS_CODE_5_OR_6_query {
	// structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket := Modbus_FUNCTIONS_CODE_5_OR_6_query{
		FUNCTION_CODE:    uint8(modbus[0]),
		REFERENCE_NUMBER: byte_decimal_array_to_decimal_uint16(modbus[1:3]),
		// wireshark represent it in heaxdecimal , i choose to represent it in decimal
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

///////////////////////////////////////////////////
// start of the linked list section  //////////////
///////////////////////////////////////////////////

/*
du au fait qu'il peut y avoir des packet qui se chevauche dans l'aordre d'arriver
il faut crée un paradigme ou les requéte (query) sont stocker en attandant leur reponce
on fait celas via une liste chainer , on stoque le port source et le payload TCP de la quéte
puis on le place dans une liste.
quand on recoit une reponse , on récupére sont port destinations , on parcour la liste
et si son port match , on récupére la valeur , et on suprime son noeud de la liste
*/
// definitions du noeud
type Node struct {
	src_port    string
	tcp_payload []byte
	next        *Node
}

// definitions de la chaine
type List struct {
	head *Node
}

// ajoute un noeud a la chaine
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

// suprime le noeud de la chaine
func (l *List) remove(value string) {
	//var wanted_modbus_payload []byte

	//fin de la chaine
	if l.head == nil {

	}
	// si valeur
	if l.head.src_port == value {
		//wanted_modbus_payload = l.head.tcp_payload
		//fmt.Printf("the query for the current responce : ", l.head.src_port)
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
	// noter que il ne peut rentrer dans la boucke car  elle et vide
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

// pritn the linked list node by node
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

// ajouter le port source et destnations
func modbusTcpParser(srcIP, dstIP net.IP, payload []byte, pkt gopacket.Packet, tcp *layers.TCP) bool {
	// define the list for the linked list
	//list := &List{}
	//var Is_query = false
	//var Is_responce = false

	modbus := pkt.TransportLayer().LayerPayload()
	transportlayer := pkt.TransportLayer()

	ip_tcp := transportlayer.(*layers.TCP)

	dstPORT := ip_tcp.DstPort.String()
	srcPORT := ip_tcp.SrcPort.String()

	//fmt.Print("source port : ", dstPORT)
	//fmt.Print("source port : ", srcPORT, "\n")

	ModbusTCP_currentPacket := viewModbusTCPEvent(modbus)
	//FunctionsCode := modbus[7]
	// define if this is a query or a responce
	// query
	if strings.Contains(dstPORT[0:4], "502(") && ModbusTCP_currentPacket.PID == uint16(0) {
		//Is_query = true
		//Is_responce = false
		list.add(srcPORT[0:5], modbus)

	}
	// response
	if strings.Contains(srcPORT[0:4], "502(") && ModbusTCP_currentPacket.PID == uint16(0) {
		//Is_responce = true
		//Is_query = false
		query_payload := get_stored_query(list, dstPORT[0:5])
		//responce_payload := modbus
		if query_payload != nil {
			//fmt.Println("\nquery paylaods : ", query_payload)
			//fmt.Println("responce paylaods : ", modbus)
			// real zone , in this time we have the query and the responce
			FunctionsCode := modbus[7]

			fmt.Println("function code detected: ", FunctionsCode)
			switch FunctionsCode {
			case READ_COILS:
				if uint16(modbus[9]) != uint16(2) {
					read_coil, responce := VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
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
					fmt.Println(" Modbus responce")
					fmt.Println("	Functions code = ", responce.FUNCTION_CODE)
					// print the value of the data byte value
					// counter for the number of byte to do
					for key, value := range responce.DATA {
						fmt.Println("coil number :", key, " || Value:", value)
					}
				} else {
					fmt.Println("Exeption code: Illegal data address")
				}
				//fmt.Println("data requested", modbus[9:])
			case READ_COIL_EXEPTION:
				fmt.Println("entering the error handeling")
				//read_coil_exeptions, responce := viewModbusTCPEvent(modbus[])
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

				fmt.Println("ERROR HANDELING : EXEPTIONS CODE :", modbus[8:], "on functions code :", READ_COILS)
			case READ_DISCRETE_INPUTS:
				if uint16(modbus[9]) != uint16(2) {
					read_discrete_input, responce := VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
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
					fmt.Println(" Modbus responce")
					fmt.Println("	Functions code = ", responce.FUNCTION_CODE)

					// print the value of the data byte value
					// counter for the number of byte to do
					for key, value := range responce.DATA {
						fmt.Println("coil number :", key, " || Value:", value)
					}
				} else {
					fmt.Println("Exeption code: Illegal data address")
				}
				//fmt.Println("data requested : ", modbus[9:])
			// functions code 3 , same concept as the read coil , but with register instead of coil.
			case READ_MULTIPLE_HOLDING_REGISTERS:
				//fmt.Println("read multiple haloding register entering functions")
				query, responce := VIEW_FUNCTIONS_CODE_3_OR_4(query_payload[7:], modbus[7:])

				//read_coil, responce := VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
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
				fmt.Println(" Modbus responce")
				fmt.Println("Functions code = ", responce.FUNCTION_CODE)
				fmt.Println("Byte count= ", responce.BYTE_COUNT)
				// print the uint16 register
				for key, value := range responce.DATA {
					fmt.Println("register number :", key, " || Value:", value)
				}

			case READ_INPUT_REGISTERS:
				query, responce := VIEW_FUNCTIONS_CODE_3_OR_4(query_payload[7:], modbus[7:])
				//read_coil, responce := VIEW_FUNCTIONS_CODE_1_OR_2(query_payload[7:], modbus[7:])
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
				fmt.Println(" Modbus responce")
				fmt.Println("Functions code = ", responce.FUNCTION_CODE)
				fmt.Println("Byte count= ", responce.BYTE_COUNT)
				// print the uint16 register
				for key, value := range responce.DATA {
					fmt.Println("register number :", key, " || Value:", value)
				}

			case WRITE_SINGLE_HOLDING_REGISTER:
				write_signle_holding_register := VIEW_FUNCTIONS_CODE_5_OR_6(modbus[7:])
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
					tui.Red("\n Modbus Responce"),
					tui.Yellow("\nFunctions code = "+strconv.FormatUint(uint64(write_signle_holding_register.FUNCTION_CODE), 10)+" WRITE_SINGLE_HOLDING_REGISTER"),
					tui.Yellow("\nReference Number = "+strconv.FormatUint(uint64(write_signle_holding_register.REFERENCE_NUMBER), 10)),
					tui.Yellow("\nData = "+strconv.FormatUint(uint64(write_signle_holding_register.DATA), 10)),
				).Push()
			case WRITE_SINGLE_COIL:
				write_signle_coil := VIEW_FUNCTIONS_CODE_5_OR_6(modbus[7:])
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
					tui.Red("\n Modbus Responce"),
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
					tui.Red("\n ModbusTCP Responce"),
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
					tui.Red("\n ModbusTCP Responce"),
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
