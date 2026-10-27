// Package wol sends Wake-on-LAN magic packets.
package wol

import (
	"bytes"
	"fmt"
	"net"
)

// Broadcast reaches every machine on the sender's LAN. Go sockets allow broadcast by default.
const Broadcast = "255.255.255.255:9"

// Packet is the magic packet for mac: 6 bytes of 0xff, then the MAC 16 times.
func Packet(mac net.HardwareAddr) []byte {
	return append(bytes.Repeat([]byte{0xff}, 6), bytes.Repeat(mac, 16)...)
}

// Send sends the magic packet for mac to addr (host:port), usually Broadcast.
func Send(mac net.HardwareAddr, addr string) error {
	if len(mac) != 6 {
		return fmt.Errorf("mac %v is not 6 bytes", mac)
	}
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(Packet(mac))
	return err
}
