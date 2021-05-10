package packets

import (
	"bytes"
	"fmt"
	"io"
	"net"
)

// Connect is the Variable Header definition for a connect control packet
type Connect struct {
	WillMessage     []byte
	Password        []byte
	Username        string
	ProtocolName    string
	ClientID        string
	WillTopic       string
	Properties      *Properties
	WillProperties  *Properties
	KeepAlive       uint16
	ProtocolVersion Version
	WillQOS         byte
	PasswordFlag    bool
	UsernameFlag    bool
	WillRetain      bool
	WillFlag        bool
	CleanStart      bool
}

// PackFlags takes the Connect flags and packs them into the single byte
// representation used on the wire by MQTT
func (c *Connect) PackFlags() (f byte) {
	if c.UsernameFlag {
		f |= 0x01 << 7
	}
	if c.PasswordFlag {
		f |= 0x01 << 6
	}
	if c.WillFlag {
		f |= 0x01 << 2
		f |= c.WillQOS << 3
		if c.WillRetain {
			f |= 0x01 << 5
		}
	}
	if c.CleanStart {
		f |= 0x01 << 1
	}
	return
}

// UnpackFlags takes the wire byte representing the connect options flags
// and fills out the appropriate variables in the struct
func (c *Connect) UnpackFlags(b byte) {
	c.CleanStart = 1&(b>>1) > 0
	c.WillFlag = 1&(b>>2) > 0
	c.WillQOS = 3 & (b >> 3)
	c.WillRetain = 1&(b>>5) > 0
	c.PasswordFlag = 1&(b>>6) > 0
	c.UsernameFlag = 1&(b>>7) > 0
}

//Unpack is the implementation of the interface required function for a packet
func (c *Connect) Unpack(r *bytes.Buffer) error {
	var err error

	if c.ProtocolName, err = readString(r); err != nil {
		return err
	}

	version, err := r.ReadByte()
	if err != nil {
		return err
	}
	if version != 3 && version != 4 && version != 5 {
		return fmt.Errorf("unknown protocol version: %d", version)
	}
	c.ProtocolVersion = Version(version)

	flags, err := r.ReadByte()
	if err != nil {
		return err
	}
	c.UnpackFlags(flags)

	if c.KeepAlive, err = readUint16(r); err != nil {
		return err
	}

	if c.ProtocolVersion == MQTTv5 {
		c.Properties = &Properties{}
		err = c.Properties.Unpack(r, CONNECT)
		if err != nil {
			return err
		}
	}

	c.ClientID, err = readString(r)
	if err != nil {
		return err
	}

	if c.WillFlag {
		if c.ProtocolVersion == MQTTv5 {
			c.WillProperties = &Properties{}
			err = c.WillProperties.Unpack(r, will)
			if err != nil {
				return err
			}
		}
		c.WillTopic, err = readString(r)
		if err != nil {
			return err
		}
		c.WillMessage, err = readBinary(r)
		if err != nil {
			return err
		}
	}

	if c.UsernameFlag {
		c.Username, err = readString(r)
		if err != nil {
			return err
		}
	}

	if c.PasswordFlag {
		c.Password, err = readBinary(r)
		if err != nil {
			return err
		}
	}

	return nil
}

// Buffers is the implementation of the interface required function for a packet
func (c *Connect) Buffers() net.Buffers {
	var cp bytes.Buffer

	writeString(c.ProtocolName, &cp)
	cp.WriteByte(byte(c.ProtocolVersion))
	cp.WriteByte(c.PackFlags())
	writeUint16(c.KeepAlive, &cp)
	if c.ProtocolVersion == MQTTv5 {
		idvp := c.Properties.Pack(CONNECT)
		encodeVBIdirect(len(idvp), &cp)
		cp.Write(idvp)
	}

	writeString(c.ClientID, &cp)
	if c.WillFlag {
		if c.ProtocolVersion == MQTTv5 {
			willIdvp := c.WillProperties.Pack(will)
			encodeVBIdirect(len(willIdvp), &cp)
			cp.Write(willIdvp)
		}
		writeString(c.WillTopic, &cp)
		writeBinary(c.WillMessage, &cp)
	}
	if c.UsernameFlag {
		writeString(c.Username, &cp)
	}
	if c.PasswordFlag {
		writeBinary(c.Password, &cp)
	}

	return net.Buffers{cp.Bytes()}
}

// WriteTo is the implementation of the interface required function for a packet
func (c *Connect) WriteTo(w io.Writer) (int64, error) {
	cp := &ControlPacket{FixedHeader: FixedHeader{Type: CONNECT}}
	cp.Content = c

	return cp.WriteTo(w)
}
