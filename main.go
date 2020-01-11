package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
)

func main() {
	from := flag.String("from", "127.0.0.1:50002", "Accept TLS connections here")
	to := flag.String("to", "127.0.0.1:50001", "Proxy to this TCP server")
	flag.Parse()

	certAndKey, err := initCertAndKey()
	if err != nil {
		log.Fatal(err)
	}

	listener, err := tls.Listen("tcp", *from, &tls.Config{
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{*certAndKey},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	for {
		connIn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		log.Println("accepted connection")
		connOut, err := net.Dial("tcp", *to)
		if err != nil {
			log.Fatal(err)
		}
		go proxy(connIn, connOut)
		go proxy(connOut, connIn)
	}
}

func proxy(in net.Conn, out net.Conn) {
	for {
		buf := make([]byte, 1024)
		reqLen, err := in.Read(buf)
		if err != nil {
			break
		}
		if reqLen != 0 {
			out.Write(buf[:reqLen])
		}
	}
	in.Close()
}
