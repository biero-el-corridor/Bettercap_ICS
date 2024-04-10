package events_stream

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"github.com/biero-el-corridor/Bettercap_ICS/session"
	//"github.com/biero-el-corridor/Bettercap_ICS/packets"
)

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

// Chain definition
type List struct {
	head *Node
}

type ModbusTCP_struct struct {
	TID    uint16 `json:"TID"`
	PID    uint16 `json:"PID"`
	Lenght uint16 `json:"Lenght"`
	UID    uint8  `json:"UID"`
}

type ModbusTCP struct {
	TID    uint16 `json:"TID"`
	PID    uint16 `json:"PID"`
	Lenght uint16 `json:"Lenght"`
	UID    uint8  `json:"UID"`
}

// Add node to chain
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
func get_stored_query(l *List, val string) []byte {
	curr := l.head
	var tcp_p []byte

	//	Note that the query cannot be analyze in the loop if it is empty
	if val == "" {
		fmt.Println("empty line found")
		return nil
	}

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

func (mod *EventsStream) viewModbusTCPEvent(output io.Writer, e session.Event) {
	fmt.Fprintf(output, "modbus event_view_modbus_tp")
}
