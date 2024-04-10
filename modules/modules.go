package modules

import (
	// biero-el-corridor gepos

	// bettercap official repos
	//"github.com/biero-el-corridor/Bettercap_ICS/modules/modbus"

	"github.com/biero-el-corridor/Bettercap_ICS/modules/any_proxy"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/api_rest"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/arp_spoof"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/ble"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/c2"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/caplets"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/dhcp6_spoof"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/dns_spoof"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/events_stream"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/gps"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/hid"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/http_proxy"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/http_server"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/https_proxy"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/https_server"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/mac_changer"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/mdns_server"

	"github.com/biero-el-corridor/Bettercap_ICS/modules/mysql_server"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/ndp_spoof"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/net_probe"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/net_recon"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/net_sniff"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/packet_proxy"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/syn_scan"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/tcp_proxy"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/ticker"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/ui"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/update"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/wifi"
	"github.com/biero-el-corridor/Bettercap_ICS/modules/wol"
	"github.com/biero-el-corridor/Bettercap_ICS/session"
)

func LoadModules(sess *session.Session) {
	sess.Register(any_proxy.NewAnyProxy(sess))
	sess.Register(arp_spoof.NewArpSpoofer(sess))
	sess.Register(api_rest.NewRestAPI(sess))
	sess.Register(ble.NewBLERecon(sess))
	sess.Register(dhcp6_spoof.NewDHCP6Spoofer(sess))
	sess.Register(net_recon.NewDiscovery(sess))
	sess.Register(dns_spoof.NewDNSSpoofer(sess))
	sess.Register(events_stream.NewEventsStream(sess))
	sess.Register(gps.NewGPS(sess))
	sess.Register(http_proxy.NewHttpProxy(sess))
	sess.Register(http_server.NewHttpServer(sess))
	sess.Register(https_proxy.NewHttpsProxy(sess))
	sess.Register(https_server.NewHttpsServer(sess))
	sess.Register(mac_changer.NewMacChanger(sess))
	sess.Register(mysql_server.NewMySQLServer(sess))
	
	sess.Register(mdns_server.NewMDNSServer(sess))
	sess.Register(net_sniff.NewSniffer(sess))
	sess.Register(packet_proxy.NewPacketProxy(sess))
	sess.Register(net_probe.NewProber(sess))
	sess.Register(syn_scan.NewSynScanner(sess))
	sess.Register(tcp_proxy.NewTcpProxy(sess))
	sess.Register(ticker.NewTicker(sess))
	sess.Register(wifi.NewWiFiModule(sess))
	sess.Register(wol.NewWOL(sess))
	sess.Register(hid.NewHIDRecon(sess))
	sess.Register(c2.NewC2(sess))
	sess.Register(ndp_spoof.NewNDPSpoofer(sess))

	sess.Register(caplets.NewCapletsModule(sess))
	sess.Register(update.NewUpdateModule(sess))
	sess.Register(ui.NewUIModule(sess))
}
