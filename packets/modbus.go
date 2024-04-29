package packets

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

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

type ModbusTCP struct {
	TID    uint16 `json:"TID"`
	PID    uint16 `json:"PID"`
	Lenght uint16 `json:"Lenght"`
	UID    uint8  `json:"UID"`
}

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

// get the byte array from the TCP payload sections from the net_sniff_modbus_tcp.go
func (cmp *ModbusTCP_struct) viewModbusTCPEvent(modbus []byte) ModbusTCP {
	// structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket := ModbusTCP{
		TID:    byte_decimal_array_to_decimal_uint16(modbus[1:3]),
		PID:    uint16(modbus[2])*1000 + uint16(modbus[3]),
		Lenght: uint16(modbus[4])*1000 + uint16(modbus[5]),
		UID:    uint8(modbus[6]),
	}
	return ModbusTCP_currentPacket
}
