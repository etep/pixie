package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	pb "pixielabs.ai/pixielabs/src/stirling/http2/testing/proto"
)

func mustCreateGrpcClientConn(address string, https bool) *grpc.ClientConn {
	// Set up a connection to the server.
	var conn *grpc.ClientConn
	var err error
	if https {
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		creds := credentials.NewTLS(tlsConfig)
		conn, err = grpc.Dial(address, grpc.WithTransportCredentials(creds))
	} else {
		conn, err = grpc.Dial(address, grpc.WithInsecure())
	}
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

func streamGreet(address string, https bool, name string) {
	conn := mustCreateGrpcClientConn(address, https)

	defer conn.Close()

	c := pb.NewStreamingGreeterClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	stream, err := c.SayHelloServerStreaming(ctx, &pb.HelloRequest{Name: name})
	if err != nil {
		log.Fatal("Failed to make streaming RPC call SayHelloServerStreaming(), error: %v", err)
	}
	for {
		item, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("SayHelloServerStreaming() failed, error: %v", err)
		}
		log.Println(item)
	}
}

func connectAndGreet(address string, https bool, name string) {
	// Set up a connection to the server.
	conn := mustCreateGrpcClientConn(address, https)

	defer conn.Close()

	c := pb.NewGreeterClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: name})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	} else {
		log.Printf("Greeting: %s", r.Message)
	}
}

func schedule(what func(), delay time.Duration) chan bool {
	stop := make(chan bool)

	go func() {
		for {
			what()
			select {
			case <-time.After(delay):
			case <-stop:
				return
			}
		}
	}()

	return stop
}

func main() {
	address := flag.String("address", "localhost:50051", "Server end point.")
	once := flag.Bool("once", false, "If true, send one request and wait for response and exit.")
	name := flag.String("name", "world", "The name to greet.")
	https := flag.Bool("https", false, "If true, uses https.")
	streaming := flag.Bool("streaming", false, "Whether or not to call streaming RPC")

	flag.Parse()

	if *once {
		connectAndGreet(*address, *https, *name)
		return
	}

	var fn func()
	if *streaming {
		fn = func() { streamGreet(*address, *https, *name) }
	} else {
		fn = func() { connectAndGreet(*address, *https, *name) }
	}
	stop := schedule(fn, 500*time.Millisecond)

	time.Sleep(60 * time.Second)
	stop <- true
	time.Sleep(1 * time.Second)
	fmt.Println("Test Done")
}
