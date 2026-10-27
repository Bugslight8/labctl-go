package wol

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestPacket(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	p := Packet(mac)
	if len(p) != 102 {
		t.Fatalf("len %d, want 102", len(p))
	}
	if !bytes.Equal(p[:6], bytes.Repeat([]byte{0xff}, 6)) {
		t.Errorf("header %x", p[:6])
	}
	for i := 0; i < 16; i++ {
		if !bytes.Equal(p[6+6*i:12+6*i], mac) {
			t.Fatalf("repeat %d = %x", i, p[6+6*i:12+6*i])
		}
	}
}

func TestSend(t *testing.T) {
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	if err := Send(mac, l.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 200)
	l.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := l.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], Packet(mac)) {
		t.Errorf("received %d bytes that are not the magic packet", n)
	}
}

func TestSendRejectsShortMAC(t *testing.T) {
	if err := Send(net.HardwareAddr{1, 2, 3}, "127.0.0.1:9"); err == nil {
		t.Error("sent a packet for a 3-byte MAC")
	}
}
