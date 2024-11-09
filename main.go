package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)

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
				} else {
					fmt.Println("msg")
					fmt.Println(msg)
					/*
						parsedMsgSplitIdx := strings.Index(string(msg), "\r\n\r\n") + 4
						msgContentStart := msg[parsedMsgSplitIdx:]
						msgContentEnd := msg[:parsedMsgSplitIdx]
						fmt.Println("msgConectStart", string(msgContentStart))
						fmt.Println("msgContentEnd", string(msgContentEnd))
					*/
				}
			}
		}()
	}
}

func decodeWsMessage(msg []byte) (string, error) {
	reader := bytes.NewReader(msg)
	head := make([]byte, 2)
	_, err := reader.ReadAt(head, 0)
	if err != nil {
		return "", err
	}

	/*
		isFragment := (head[0] & 0x80) == 0x00
		isOpcode := head[0] & 0x0F
		reserverd := (head[0] & 0x70)
		isMasked := (head[1] & 0x80) == 0x80
	*/
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

	mask := msg[startFrom : startFrom+4]
	payload := make([]byte, length)
	reader.ReadAt(payload, int64(startFrom)+4)
	for i := uint64(0); i < length; i++ {
		payload[i] ^= mask[i%4]
	}

	return string(payload), nil
}
