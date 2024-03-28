package packets

//"net"
//"strings"

// "github.com/evilsocket/islazy/str"
// "github.com/google/gopacket"
// "github.com/google/gopacket/layers"
type ModbusTCP_struct struct {
	TID    uint16 `json:"TID"`
	PID    uint16 `json:"PID"`
	Lenght uint16 `json:"Lenght"`
	UID    uint8  `json:"UID"`
}

func octalToDecimal(octal uint16) uint16 {
	decimal := uint16(0)
	base := uint16(1)
	for octal != 0 {
		remainder := octal % 10
		decimal += remainder * base
		base *= 8
		octal /= 10
	}
	return decimal
}

//debug PoC funtions

// get the byte array from the TCP payload sections from the net_sniff_modbus_tcp.go
func (cmp *ModbusTCP_struct) viewModbusTCPEvent(modbus []byte) ModbusTCP_struct {
	// structure of the current modbusTCP sections of the packet
	ModbusTCP_currentPacket := ModbusTCP_struct{
		TID:    octalToDecimal(uint16(modbus[0])*1000 + uint16(modbus[1])),
		PID:    uint16(modbus[2])*1000 + uint16(modbus[3]),
		Lenght: uint16(modbus[4])*1000 + uint16(modbus[5]),
		UID:    uint8(modbus[6]),
	}
	return ModbusTCP_currentPacket
}
