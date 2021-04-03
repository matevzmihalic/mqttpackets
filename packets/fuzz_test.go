package packets

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/eclipse/paho.mqtt.golang/packets"
	fuzz "github.com/google/gofuzz"
)

func TestFuzzingV311(t *testing.T) {
	tests := []struct {
		packetType byte
		fuzzer     *fuzz.Fuzzer
	}{
		{
			packetType: packets.Connect,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.ConnectPacket, c fuzz.Continue) {
					p.ProtocolName = "MQTT"
					p.ProtocolVersion = byte(MQTTv311)
					p.CleanSession = c.RandBool()
					p.WillFlag = c.RandBool()
					if p.WillFlag {
						p.WillQos = byte(c.Intn(2))
						p.WillRetain = c.RandBool()
						p.WillTopic = c.RandString()
						p.WillMessage = []byte(c.RandString())
					}
					p.UsernameFlag = c.RandBool()
					if p.UsernameFlag {
						p.Username = c.RandString()
					}
					p.PasswordFlag = c.RandBool()
					if p.PasswordFlag {
						p.Password = []byte(c.RandString())
					}
					p.Keepalive = uint16(c.RandUint64())
					p.ClientIdentifier = c.RandString()

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(2))
				},
			),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(packets.PacketNames[tc.packetType], func(t *testing.T) {
			for i := 0; i < 50000; i++ {
				fuzzV311Packet(t, tc.fuzzer, tc.packetType)
			}
		})
	}
}

func fuzzV311Packet(t *testing.T, fuzzer *fuzz.Fuzzer, packetType byte) {
	packet := packets.NewControlPacket(packetType)
	fuzzer.Fuzz(packet)

	originalData := bytes.NewBuffer(nil)
	err := packet.Write(originalData)
	if err != nil {
		t.Errorf("original packet write fail: %s", err)
	}

	newPacket, err := ReadPacket(bytes.NewReader(originalData.Bytes()), MQTTv311)
	if err != nil {
		t.Errorf("packet read fail: %s", err)
	}

	newData := bytes.NewBuffer(nil)
	newPacket.WriteTo(newData)

	if !bytes.Equal(originalData.Bytes(), newData.Bytes()) {
		t.Errorf("expected:\n\n%s\ngot:\n\n%s", hex.Dump(originalData.Bytes()), hex.Dump(newData.Bytes()))
	}
}
