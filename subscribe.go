package mqttpackets

import (
	"bytes"
	"io"
	"net"
)

// Subscribe is the Variable Header definition for a Subscribe control packet
type Subscribe struct {
	Properties    *Properties
	Subscriptions []Subscription
	PacketID      uint16
}

// Subscription is the struct representing a subscription and its options
type Subscription struct {
	Topic             string
	QoS               byte
	RetainHandling    byte
	NoLocal           bool
	RetainAsPublished bool
}

// WriteTo writes a subscription to buffer
func (s *Subscription) WriteTo(b *bytes.Buffer) {
	writeString(s.Topic, b)
	var ret byte
	ret |= s.QoS & 0x03
	if s.NoLocal {
		ret |= 1 << 2
	}
	if s.RetainAsPublished {
		ret |= 1 << 3
	}
	ret |= s.RetainHandling & 0x30
	b.WriteByte(ret)
}

// Unpack is the implementation of the interface required function for a packet
func (s *Subscription) Unpack(r *bytes.Buffer) error {
	topic, err := readString(r)
	if err != nil {
		return err
	}
	s.Topic = topic

	b, err := r.ReadByte()
	if err != nil {
		return err
	}

	s.QoS = b & 0x03
	s.NoLocal = (b & 1 << 2) == 1
	s.RetainAsPublished = (b & 1 << 3) == 1
	s.RetainHandling = b & 0x30

	return nil
}

// Unpack is the implementation of the interface required function for a packet
func (s *Subscribe) Unpack(r *bytes.Buffer) error {
	var err error
	s.PacketID, err = readUint16(r)
	if err != nil {
		return err
	}

	if s.Properties != nil {
		err = s.Properties.Unpack(r, SUBSCRIBE)
		if err != nil {
			return err
		}
	}

	for r.Len() > 0 {
		var so Subscription
		if err = so.Unpack(r); err != nil {
			return err
		}
		s.Subscriptions = append(s.Subscriptions, so)
	}

	return nil
}

// Buffers is the implementation of the interface required function for a packet
func (s *Subscribe) Buffers() net.Buffers {
	var b bytes.Buffer
	writeUint16(s.PacketID, &b)
	var subs bytes.Buffer
	for _, o := range s.Subscriptions {
		o.WriteTo(&subs)
	}
	if s.Properties == nil {
		return net.Buffers{b.Bytes(), subs.Bytes()}
	}

	idvp := s.Properties.Pack(SUBSCRIBE)
	propLen := encodeVBI(len(idvp))
	return net.Buffers{b.Bytes(), propLen, idvp, subs.Bytes()}
}

// WriteTo is the implementation of the interface required function for a packet
func (s *Subscribe) WriteTo(w io.Writer) (int64, error) {
	cp := &ControlPacket{FixedHeader: FixedHeader{Type: SUBSCRIBE, Flags: 2}}
	cp.Content = s

	return cp.WriteTo(w)
}
