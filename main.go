package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"sync"

	"github.com/google/uuid"
)

type clientConnection struct {
	netCon *net.TCPConn
	closed bool
	id     string
}

type message struct {
	isFragment bool
	opcode     byte
	reserverd  byte
	isMasked   bool
	length     uint64
	payload    []byte
	clientId   string
}

type connections struct {
	conns    []*clientConnection
	mu       sync.Mutex
	len      uint64
	messages chan message
}

func (c *connections) addClient(con *net.TCPConn) *clientConnection {
	c.mu.Lock()
	defer c.mu.Unlock()

	id := uuid.New().String()
	newCon := &clientConnection{
		netCon: con,
		id:     id,
	}

	c.conns = append(c.conns, newCon)
	c.len += 1

	return newCon
}

func (c *connections) broadcast() {
	for {
		select {
		case msg := <-c.messages:
			fmt.Println("got msg: ", string(msg.payload))

			encodedMsg, err := encodeWsMessage(msg)
			if err != nil {
				panic(fmt.Sprintf("could not encode ws message!! %+v\n", err))
			}
			for _, client := range c.conns {
				if msg.clientId == client.id || client.closed {
					continue
				}

				_, err := client.netCon.Write(encodedMsg)
				if err != nil {
					client.closed = true
				}
			}

			if c.len == 0 {
				continue
			}

			aliveCons := []*clientConnection{}
			for _, client := range c.conns {
				if !client.closed {
					aliveCons = append(aliveCons, client)
				} else {
					client.netCon.Close()
				}
			}
			c.len = uint64(len(aliveCons))
			c.mu.Lock()
			c.conns = aliveCons
			c.mu.Unlock()
		default:
			continue
		}
	}
}

var serverConnections = connections{}

func main() {
	server, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		log.Fatalf("could not start tcp server %+v\n", err)
		return
	}
	defer server.Close()

	serverConnections.mu = sync.Mutex{}
	serverConnections.messages = make(chan message)

	fmt.Println("listening to connections at localhost:8080")
	go serverConnections.broadcast()

	for {
		con, err := server.Accept()
		if err != nil {
			fmt.Printf("failed to accept connection: %+v\n", err)
			return
		}
		tcpCon := con.(*net.TCPConn)

		go handleConnection(tcpCon)
	}
}

func handleConnection(con *net.TCPConn) {
	myCon := serverConnections.addClient(con)
	for {
		msg := make([]byte, 1024)
		_, err := myCon.netCon.Read(msg)
		if err != nil {
			if err.Error() == "EOF" {
				continue
			}
			fmt.Printf("could not read message from client: %+v\n", err)
			return
		}

		if strings.Contains(string(msg[:3]), "GET") {
			err := myCon.handleUpgradeToWs(msg)
			if err != nil {
				return
			}
		} else {
			fmt.Println("get msg")
			decodedMsg, err := decodeWsMessage(msg)
			if err != nil {
				fmt.Printf("could not decode msg: %+v\n", err)
				continue
			}
			decodedMsg.clientId = myCon.id

			fmt.Println("decded: ", string(decodedMsg.payload))

			serverConnections.messages <- decodedMsg
			fmt.Println("added to chan")
		}
	}

}

func (client *clientConnection) handleUpgradeToWs(handshake []byte) error {
	headers := strings.Split(string(handshake), "\n")
	secretKey := ""
	for _, hdr := range headers {
		if strings.Contains(hdr, "Sec-WebSocket-Key: ") {
			secretKey = strings.TrimSpace(strings.Split(hdr, ":")[1])
		}
	}

	if secretKey == "" {
		fmt.Println("Sec-WebSocket-Key not found in headers")
		return errors.New("No secret provided")
	}

	concatWithWsKey := secretKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	hasher := sha1.New()
	hasher.Write([]byte(concatWithWsKey))
	serverSecret := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Println(serverSecret)

	upgradeStr := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept:" + serverSecret + "\r\n" +
		"Upgrade: websocket\r\n" +
		"\r\n"
	_, err := client.netCon.Write([]byte(upgradeStr))
	if err != nil {
		fmt.Printf("failed to send upgrade string: %+v\n", err)
		return fmt.Errorf("failed to send upgrade response to client: %+v", err)
	}

	return nil

}

func decodeWsMessage(msg []byte) (message, error) {
	message := message{}

	reader := bytes.NewReader(msg)
	head := make([]byte, 2)
	_, err := reader.ReadAt(head, 0)
	if err != nil {
		return message, err
	}

	message.isFragment = (head[0] & 0x80) == 0x00
	message.opcode = head[0] & 0x0F
	message.reserverd = (head[0] & 0x70)
	message.isMasked = (head[1] & 0x80) == 0x80
	var length uint64
	length = uint64(head[1] & 0x7F)
	startFrom := 2
	if length == 126 {
		data := msg[startFrom:4]
		startFrom = 4
		length = uint64(binary.BigEndian.Uint16(data))
	} else if length == 127 {
		data := msg[startFrom:8]
		length = uint64(binary.BigEndian.Uint64(data))
		startFrom = 8
	}

	message.length = length

	mask := msg[startFrom : startFrom+4]
	payload := make([]byte, length)
	reader.ReadAt(payload, int64(startFrom)+4)
	for i := uint64(0); i < length; i++ {
		payload[i] ^= mask[i%4]
	}

	message.payload = payload

	return message, nil
}

func encodeWsMessage(msg message) ([]byte, error) {
	data := make([]byte, 2)
	data[0] = 0x80 | msg.opcode

	if msg.isFragment {
		data[0] &= 0x7F
	}

	if msg.length <= 125 {
		data[1] = byte(msg.length)
		data = append(data, msg.payload...)
	} else if msg.length > 125 && float64(msg.length) < math.Pow(2, 16) {
		data[1] = byte(126)
		size := make([]byte, 2)
		binary.BigEndian.PutUint16(size, uint16(msg.length))
		data = append(data, size...)
		data = append(data, msg.payload...)
	} else if float64(msg.length) >= math.Pow(2, 16) {
		data[1] = byte(127)
		size := make([]byte, 8)
		binary.BigEndian.PutUint64(size, msg.length)
		data = append(data, size...)
		data = append(data, msg.payload...)
	}

	return data, nil
}

func (c *clientConnection) closeWsConnMsg() error {
	c.closed = true
	msg := message{}
	msg.opcode = 8
	msg.length = 2
	msg.payload = make([]byte, 2)
	binary.BigEndian.PutUint16(msg.payload, 1005)

	encoded, err := encodeWsMessage(msg)
	if err != nil {
		return err
	}

	_, err = c.netCon.Write(encoded)
	return err
}
