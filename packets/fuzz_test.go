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
						p.WillQos = byte(c.Intn(3))
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
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Connack,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.ConnackPacket, c fuzz.Continue) {
					p.SessionPresent = c.RandBool()
					p.ReturnCode = byte(c.Intn(6))

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Disconnect,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.DisconnectPacket, c fuzz.Continue) {
					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Pingreq,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.PingreqPacket, c fuzz.Continue) {
					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Pingresp,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.PingrespPacket, c fuzz.Continue) {
					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Puback,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.PubackPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Pubcomp,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.PubcompPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Publish,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.PublishPacket, c fuzz.Continue) {
					p.TopicName = c.RandString()
					p.MessageID = uint16(c.RandUint64())
					p.Payload = []byte(c.RandString())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Pubrec,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.PubrecPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Pubrel,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.PubrelPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Suback,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.SubackPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())
					p.ReturnCodes = make([]byte, c.Intn(20))
					for i := range p.ReturnCodes {
						p.ReturnCodes[i] = byte(c.Intn(4))
						if p.ReturnCodes[i] == 3 {
							p.ReturnCodes[i] = 0x80
						}
					}

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Subscribe,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.SubscribePacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())
					p.Topics = make([]string, c.Intn(10))
					p.Qoss = make([]byte, len(p.Topics))
					for i := range p.Topics {
						p.Topics[i] = c.RandString()
						p.Qoss[i] = byte(c.Intn(3))
					}

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Unsuback,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.UnsubackPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: packets.Unsubscribe,
			fuzzer: fuzz.New().Funcs(
				func(p *packets.UnsubscribePacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())
					p.Topics = make([]string, c.Intn(10))
					for i := range p.Topics {
						p.Topics[i] = c.RandString()
					}

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(packets.PacketNames[tc.packetType], func(t *testing.T) {
			for i := 0; i < 100000; i++ {
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
		return
	}

	newPacket, err := ReadPacket(bytes.NewReader(originalData.Bytes()), MQTTv311)
	if err != nil {
		t.Errorf("packet read fail: %s", err)
		return
	}

	newData := bytes.NewBuffer(nil)
	newPacket.WriteTo(newData)

	if !bytes.Equal(originalData.Bytes(), newData.Bytes()) {
		t.Errorf("expected:\n\n%s\ngot:\n\n%s", hex.Dump(originalData.Bytes()), hex.Dump(newData.Bytes()))
	}
}
