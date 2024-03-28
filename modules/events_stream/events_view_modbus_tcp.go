package events_stream

import (
	"fmt"
	"io"


	"github.com/bettercap/bettercap/session"


)


func (mod *EventsStream) viewModbusTCPEvent(output io.Writer, e session.Event) {
	fmt.Fprintf(output, "modbus event_view_modbus_tp")
}