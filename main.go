package main

import (
	"crypto/sha1"
	"encoding/base64"
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
			msg := make([]byte, 1024)
			_, err := con.Read(msg)
			if err != nil {
				fmt.Printf("could not read message from client: %+v\n", err)
			}

			fmt.Println(string(msg))

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
				fmt.Println(string(msg))
				parsedMsgSplitIdx := strings.Index(string(msg), "\r\n\r\n") + 4
				msgContentStart := msg[parsedMsgSplitIdx:]
				msgContentEnd := msg[:parsedMsgSplitIdx]
				fmt.Println("msgConectStart", msgContentStart)
				fmt.Println("msgContentEnd", msgContentEnd)
			}
		}()
	}
}
