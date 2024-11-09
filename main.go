package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"strings"
)

type clientConnection struct {
	netCon net.Conn
	hashId string
}

type message struct {
	isFragment bool
	opcode     byte
	reserverd  byte
	isMasked   bool
	length     uint64
	payload    []byte
}

var connections = map[string]*clientConnection{}

func main() {
	server, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		log.Fatalf("could not start tcp server %+v\n", err)
		return
	}
	defer server.Close()

	fmt.Println("listening to connections at localhost:8080")

	for {
		con, err := server.Accept()
		if err != nil {
			fmt.Printf("failed to accept connection: %+v\n", err)
			return
		}

		go func() {
			for {
				msg := make([]byte, 1024)
				_, err := con.Read(msg)
				if err != nil {
					fmt.Printf("could not read message from client: %+v\n", err)
				}

				if strings.Contains(string(msg), "GET") {
					fmt.Println("upgrade")
					headers := strings.Split(string(msg), "\n")
					secretKey := ""
					for _, hdr := range headers {
						if strings.Contains(hdr, "Sec-WebSocket-Key: ") {
							secretKey = strings.TrimSpace(strings.Split(hdr, ":")[1])
						}
					}

					if secretKey == "" {
						fmt.Println("Sec-WebSocket-Key not found in headers")
						con.Close()
						return
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
					_, err := con.Write([]byte(upgradeStr))
					if err != nil {
						fmt.Printf("failed to send upgrade string: %+v\n", err)
					}

					connections[secretKey] = &clientConnection{
						netCon: con,
						hashId: serverSecret,
					}
				} else {
					fmt.Println("msg")
					decodedMsg, err := decodeWsMessage(msg)
					if err != nil {
						fmt.Printf("could not decode msg: %+v\n", err)
					}

					fmt.Println("decoded msg: ", string(decodedMsg.payload))
					for _, sc := range connections {
						encodedData, err := encodeWsMessage(decodedMsg)
						if err != nil {
							fmt.Println("could not encode msg data: ", err)
						}
						_, err = sc.netCon.Write(encodedData)
						if err != nil {
							fmt.Println("could not send message to client", err)
						}
					}
				}
			}
		}()
	}
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
