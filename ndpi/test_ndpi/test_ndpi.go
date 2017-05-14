package main

import (
	"fmt"
	"log"
	"ndpi-go/ndpi"
	"os"
	"zapret_parser/logutils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile = "http.cap"
	handle   *pcap.Handle
	err      error
)

func main() {

	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: logutils.LogLevel("DEBUG"),
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)

	// Open file instead of device
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		log.Printf("[DEBUG] packet: %s", packet)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			log.Println("[DEBUG] IPv4 detected")
		} else {
			ipLayer = packet.Layer(layers.LayerTypeIPv6)
			if ipLayer != nil {
				log.Println("[DEBUG] IPv6 detected")
			} else {
				log.Printf("[ERROR] Unsupported IP protocol version for packet %s", packet)
				continue
			}
		}

	}

	ndpi.Init()

	fmt.Println("-- ")
}
