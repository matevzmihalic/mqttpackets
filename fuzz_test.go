package packets

import (
	"bytes"
	"encoding/hex"
	"testing"

	v5packets "github.com/eclipse/paho.golang/packets"
	v3packets "github.com/eclipse/paho.mqtt.golang/packets"
	fuzz "github.com/google/gofuzz"
)

func TestFuzzingV311(t *testing.T) {
	tests := []struct {
		packetType byte
		fuzzer     *fuzz.Fuzzer
	}{
		{
			packetType: v3packets.Connect,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.ConnectPacket, c fuzz.Continue) {
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
			packetType: v3packets.Connack,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.ConnackPacket, c fuzz.Continue) {
					p.SessionPresent = c.RandBool()
					p.ReturnCode = byte(c.Intn(6))

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Disconnect,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.DisconnectPacket, c fuzz.Continue) {
					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Pingreq,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.PingreqPacket, c fuzz.Continue) {
					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Pingresp,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.PingrespPacket, c fuzz.Continue) {
					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Puback,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.PubackPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Pubcomp,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.PubcompPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Publish,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.PublishPacket, c fuzz.Continue) {
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
			packetType: v3packets.Pubrec,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.PubrecPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Pubrel,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.PubrelPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Suback,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.SubackPacket, c fuzz.Continue) {
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
			packetType: v3packets.Subscribe,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.SubscribePacket, c fuzz.Continue) {
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
			packetType: v3packets.Unsuback,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.UnsubackPacket, c fuzz.Continue) {
					p.MessageID = uint16(c.RandUint64())

					p.Dup = c.RandBool()
					p.Retain = c.RandBool()
					p.Qos = byte(c.Intn(3))
				},
			),
		},
		{
			packetType: v3packets.Unsubscribe,
			fuzzer: fuzz.New().Funcs(
				func(p *v3packets.UnsubscribePacket, c fuzz.Continue) {
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
		t.Run(v3packets.PacketNames[tc.packetType], func(t *testing.T) {
			for i := 0; i < 100000; i++ {
				fuzzV311Packet(t, tc.fuzzer, tc.packetType)
			}
		})
	}
}

func fuzzV311Packet(t *testing.T, fuzzer *fuzz.Fuzzer, packetType byte) {
	packet := v3packets.NewControlPacket(packetType)
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

func TestFuzzingV5(t *testing.T) {
	tests := []struct {
		packetType byte
		fuzzer     *fuzz.Fuzzer
	}{
		{
			packetType: v5packets.CONNECT,
			fuzzer: fuzz.New().Funcs(
				func(p *v5packets.Connect, c fuzz.Continue) {
					p.ProtocolName = "MQTT"
					p.ProtocolVersion = byte(MQTTv5)
					p.CleanStart = c.RandBool()
					p.WillFlag = c.RandBool()
					if p.WillFlag {
						p.WillQOS = byte(c.Intn(3))
						p.WillRetain = c.RandBool()
						p.WillTopic = c.RandString()
						p.WillMessage = []byte(c.RandString())
						p.WillProperties = &v5packets.Properties{}
						// uncomment when paho.golang fixes allowed will properties
						//if c.RandBool() {
						//	i := c.Uint32()
						//	p.WillProperties.WillDelayInterval = &i
						//}
						//if c.RandBool() {
						//	var format byte
						//	if c.RandBool() {
						//		format = 1
						//	}
						//	p.WillProperties.PayloadFormat = &format
						//}
						//if c.RandBool() {
						//	expiry := c.Uint32()
						//	p.WillProperties.MessageExpiry = &expiry
						//}
						//if c.RandBool() {
						//	p.WillProperties.ContentType = c.RandString()
						//}
						//if c.RandBool() {
						//	p.WillProperties.ResponseTopic = c.RandString()
						//}
						//if c.RandBool() {
						//	p.WillProperties.CorrelationData = []byte(c.RandString())
						//}
						userProperties(p.WillProperties, c)
					}
					p.UsernameFlag = c.RandBool()
					if p.UsernameFlag {
						p.Username = c.RandString()
					}
					p.PasswordFlag = c.RandBool()
					if p.PasswordFlag {
						p.Password = []byte(c.RandString())
					}
					p.KeepAlive = uint16(c.RandUint64())
					p.ClientID = c.RandString()

					p.Properties = &v5packets.Properties{}
					if c.RandBool() {
						i := c.Uint32()
						p.Properties.SessionExpiryInterval = &i
					}
					if c.RandBool() {
						p.Properties.AuthMethod = c.RandString()
					}
					if c.RandBool() {
						p.Properties.AuthData = []byte(c.RandString())
					}
					if c.RandBool() {
						var info byte
						if c.RandBool() {
							info = 1
						}
						p.Properties.RequestProblemInfo = &info
					}
					if c.RandBool() {
						var info byte
						if c.RandBool() {
							info = 1
						}
						p.Properties.RequestResponseInfo = &info
					}
					if c.RandBool() {
						i := uint16(c.Uint32())
						p.Properties.ReceiveMaximum = &i
					}
					if c.RandBool() {
						i := uint16(c.Uint32())
						p.Properties.TopicAliasMaximum = &i
					}
					if c.RandBool() {
						q := byte(c.Intn(3))
						p.Properties.MaximumQOS = &q
					}
					if c.RandBool() {
						i := c.Uint32()
						p.Properties.MaximumPacketSize = &i
					}
					userProperties(p.Properties, c)
				},
			),
		},
	}

	for _, tc := range tests {
		tc := tc
		packet := NewControlPacket(tc.packetType, MQTTv5)

		t.Run(packet.PacketType(), func(t *testing.T) {
			for i := 0; i < 100000; i++ {
				fuzzV5Packet(t, tc.fuzzer, tc.packetType)
			}
		})
	}
}

func fuzzV5Packet(t *testing.T, fuzzer *fuzz.Fuzzer, packetType byte) {
	packet := v5packets.NewControlPacket(packetType)
	fuzzer.Fuzz(packet.Content)

	originalData := bytes.NewBuffer(nil)
	_, err := packet.WriteTo(originalData)
	if err != nil {
		t.Errorf("original packet write fail: %s", err)
		return
	}

	newPacket, err := ReadPacket(bytes.NewReader(originalData.Bytes()), MQTTv5)
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

func userProperties(properties *v5packets.Properties, c fuzz.Continue) {
	if c.RandBool() {
		properties.User = make([]v5packets.User, c.Intn(10))
		for i := range properties.User {
			properties.User[i] = v5packets.User{
				Key:   c.RandString(),
				Value: c.RandString(),
			}
		}
	}
}
