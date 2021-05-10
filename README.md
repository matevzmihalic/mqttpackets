MQTT packets [![Go Reference](https://pkg.go.dev/badge/github.com/matevzmihalic/mqttpackets.svg)](https://pkg.go.dev/github.com/matevzmihalic/mqttpackets)
============

is a Go module for decoding and encoding v3 and v5 MQTT packets.
It's based on [https://github.com/eclipse/paho.golang](https://github.com/eclipse/paho.golang)
which supports only v5 version and also includes MQTT client. 

Installation
------------

Install with the standard go tools:
```shell
go get github.com/matevzmihalic/mqttpackets
```

Basic usage
-----------

```go
import "github.com/matevzmihalic/mqttpackets"

// read packet from incoming connection
packet, err := mqttpackets.ReadPacket(inConn, 0)
if err != err {
	return err
}

// first packet in MQTT connection should always be CONNECT packet
connectPacket, ok := packet.Content.(*mqttpackets.Connect)
if !ok {
    return fmt.Errorf("first packet should be CONNECT")
}

// get version from CONNECT packet and save it for later
version := connectPacket.ProtocolVersion

// write the first packet to outgoing connection
_, err := packet.WriteTo(outConn)
if err != err {
    return err
}

// read next packet with the correct MQTT version for the connection
packet, err = mqttpackets.ReadPacket(inConn, version)
if err != err {
    return err
}

// create a custom PUBLISH packet
newPacket := mqttpackets.NewControlPacket(mqttpackets.PUBLISH, version)
publishPacket := newPacket.Content.(*mqttpackets.Publish)
publishPacket.Topic = "sensor/temp"
publishPacket.QoS = 1
publishPacket.Payload = []byte("23.56")

_, err = newPacket.WriteTo(outConn)
if err != err {
    return err
}
```
