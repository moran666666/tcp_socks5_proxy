package main

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log"
	"net"
	"os"

	"github.com/armon/go-socks5"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "proxytcp"
	app.Version = "1.0.0"
	app.Usage = "tcp proxy server"
	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:  "server, s",
			Usage: "enable server mode",
		},
		&cli.BoolFlag{
			Name:  "client, c",
			Usage: "enable client mode",
		},
		&cli.StringFlag{
			Name:  "listen, l",
			Value: "0.0.0.0:21666",
			Usage: "proxy server listen address",
		},
		&cli.StringFlag{
			Name:  "remoteaddr, r",
			Value: "127.0.0.1:61666",
			Usage: "remote server address",
		},
		&cli.StringFlag{
			Name:  "key, k",
			Value: "examplekey123456",
			Usage: "set encryption key",
		},
	}
	app.Action = func(c *cli.Context) {
		enableServer := c.Bool("server")
		listenAddr := c.String("listen")
		remoteAddr := c.String("remoteaddr")
		passKey := c.String("key")

		// 服务端开启 socks5 代理服务
		dstAddr := remoteAddr
		socks5Addr := "127.0.0.1:1080"
		if enableServer {
			dstAddr = socks5Addr
			conf := &socks5.Config{}
			server, err := socks5.New(conf)
			if err != nil {
				log.Println("Error:", err)
			}

			go server.ListenAndServe("tcp", socks5Addr)
			log.Println("socks5 proxy started on", socks5Addr)
		}

		listener, err := net.Listen("tcp", listenAddr)
		if err != nil {
			log.Println("Error:", err)
			os.Exit(1)
		}
		log.Println("Local server started on: ", listenAddr)

		defer listener.Close()

		log.Println("--server: ", enableServer)
		log.Println("dstAddr: ", dstAddr)

		for {
			srcConn, err := listener.Accept()
			if err != nil {
				log.Println("Error:", err)
			}
			log.Println("New connection from: ", srcConn.RemoteAddr())

			go handleConn(srcConn, dstAddr, []byte(passKey), enableServer)
		}
	}
	app.Run(os.Args)

	done := make(chan bool)
	<-done
}

// 处理连接
func handleConn(srcConn net.Conn, dstAddr string, key []byte, enableServer bool) {
	defer srcConn.Close()
	dstConn, err := net.Dial("tcp", dstAddr) // 服务端的 SOCKS5 代理地址
	if err != nil {
		log.Println("Error connecting to destination:", err)
		return
	}
	defer dstConn.Close()

	iv := make([]byte, aes.BlockSize)
	block, err := aes.NewCipher(key) // 创建AES块， 注意：key密钥长度必须为16, 24或32字节
	if err != nil {
		log.Println("Error creating cipher block:", err)
		return
	}

	encryptStream := cipher.NewCFBEncrypter(block, iv) // 创建加密流
	decryptStream := cipher.NewCFBDecrypter(block, iv) // 创建解密流

	if enableServer {
		// 服务端双向数据转发
		go func() {
			reader := &cipher.StreamReader{S: decryptStream, R: srcConn} // 代理输入 -> 网络连接（解密）
			io.Copy(dstConn, reader)
		}()

		writer := &cipher.StreamWriter{S: encryptStream, W: srcConn} // 网络连接 -> 代理输出（加密）
		io.Copy(writer, dstConn)
	} else {
		// 客户端双向数据转发
		go func() {
			writer := &cipher.StreamWriter{S: encryptStream, W: dstConn} // 代理输入 -> 网络连接（加密）
			io.Copy(writer, srcConn)
		}()

		reader := &cipher.StreamReader{S: decryptStream, R: dstConn} // 网络连接 -> 代理输出（解密）
		io.Copy(srcConn, reader)
	}
}
