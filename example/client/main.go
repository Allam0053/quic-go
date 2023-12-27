package main

import (
	"C"

	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"

	"fmt"
	"io"

	// "io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	// "github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

//export QuicExecutable
func QuicExecutable(url string) string {
	verbose := flag.Bool("v", true, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", true, "skip certificate verification")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")
	// flag.Parse()
	// urls := flag.Args()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	// return "success"
	//#region ========== old cert pool code ==========
	// pool, err := x509.SystemCertPool()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// testdata.AddRootCA(pool)
	//#endregion ======= old cert pool code ==========

	//#region ========== new cert pool code ==========
	// Load certificates from assets
	certFile, err := os.ReadFile("assets/cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certFile)
	//#endregion ======= new cert pool code ==========

	var qconf quic.Config
	if *enableQlog {
		qconf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			filename := fmt.Sprintf("client_%s.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return qlog.NewConnectionTracer(utils.NewBufferedWriteCloser(bufio.NewWriter(f), f), p, connID)
		}
	}
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var result string
	rsp, err := hclient.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	logger.Infof("Got response for %s: %#v", url, rsp)

	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)
	if err != nil {
		log.Fatal(err)
	}
	if *quiet {
		logger.Infof("\nResponse Body: %d bytes\n", body.Len())
	} else {
		logger.Infof("\n\n\n//#region =========== Response Body ===========")
		logger.Infof("%s", body.Bytes())
		logger.Infof("//#endregion ======== Response Body ===========\n\n\n")

	}

	return result;
	
}

func main() {
	flag.Parse()
	urls := flag.Args()

	logger := utils.DefaultLogger
	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		logger.Infof("GET %s", addr)
		go func(addr string) {
			logger.Infof("GET %s", addr)
			QuicExecutable(addr)
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
/*
func main() {
	verbose := flag.Bool("v", true, "verbose")
	quiet := flag.Bool("q", false, "don't print the data")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", true, "skip certificate verification")
	enableQlog := flag.Bool("qlog", true, "output a qlog (in the same directory)")
	flag.Parse()
	urls := flag.Args()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	testdata.AddRootCA(pool)

	var qconf quic.Config
	if *enableQlog {
		qconf.Tracer = func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			filename := fmt.Sprintf("client_%s.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return qlog.NewConnectionTracer(utils.NewBufferedWriteCloser(bufio.NewWriter(f), f), p, connID)
		}
	}
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: &qconf,
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for _, addr := range urls {
		logger.Infof("GET %s", addr)
		go func(addr string) {
			rsp, err := hclient.Get(addr)
			if err != nil {
				log.Fatal(err)
			}
			logger.Infof("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if *quiet {
				logger.Infof("\nResponse Body: %d bytes\n", body.Len())
			} else {
				logger.Infof("\n\n\n//#region =========== Response Body ===========")
				logger.Infof("%s", body.Bytes())
				logger.Infof("//#endregion ======== Response Body ===========\n\n\n")
				
				//#region ================== write file with response body here ==================
				// Write body to a file
				filename := fmt.Sprintf("response_body.txt")
				err := ioutil.WriteFile(filename, body.Bytes(), 0644)
				if err != nil {
					log.Fatal(err)
				}
				logger.Infof("Response body written to file: %s", filename)
				//#endregion =============== write file with response body here ==================

			}
			wg.Done()
		}(addr)
	}
	wg.Wait()
}
*/

/*
env CGO_ENABLED=1 GOOS=android GOARCH=arm64 GOARM=7 CC=~/Documents/android-ndk-r26b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang go build -o libclient_android_arm64.so -buildmode=c-shared main.go

2002  go run main.go https://google.com/
 2003  go build -o libclient.so -buildmode=c-shared main.go
 2004  go run main.go https://google.com/
 2005  go build -o libclient.so -buildmode=c-shared main.go
 2006  go env GOARCH
 2007  export GOARCH=arm64
 2008  go env GOARCH
 2009  go build -o libclient.so -buildmode=c-shared main.go
 2010  ls
 2011  file libclient.so
 2012  env GOOS=linux GOARCH=arm64 go build -o prepnode_arm64
 2013  ls
 2014  file prepnode_arm64
 2015  env GOOS=linux GOARCH=arm64 go build -o libclient.so -buildmode=c-shared main.go
 2016  ls
 2017  go tool dist list
 2018  env GOOS=linux GOARCH=android/arm64 go build -o libclient.so -buildmode=c-shared main.go
 2019  env GOOS=android GOARCH=arm64 go build -o libclient.so -buildmode=c-shared main.go
 2020  env GOOS=android GOARCH=arm64 go build -o libclient_android_arm64
 2021  file libclient_android_arm64
 2022  file libclient_amd64_x86_64.so
 2023  nm libclient_android_arm64 | grep quicExecutable
 2024  nm libclient_android_arm64 | grep main.quicExecutable
 2025  nm libclient_android_arm64
 2026  nm --help
 2027  nm libclient_android_arm64 | grep quicExecutable
 2028  ldd libclient_android_arm64
 2029  env CGO=ENABLED=1 GOOS=android GOARCH=arm64 go build -o libclient_android_arm64
 2030  ldd libclient_android_arm64
 2031  env CGO=ENABLED=1 GOOS=android GOARCH=arm64 go build -o libclient_android_arm64 -buildmode=c-shared
 2032  env CGO=ENABLED=1 GOOS=android GOARCH=arm64 go build -o libclient_android_arm64.so -buildmode=c-shared main.go
 2033  env CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -o libclient_android_arm64.so -buildmode=c-shared main.go
 2034  allam@allam-X450CC:~/Documents/equnix/quic-go/example/client$ env CGO=ENABLED=1 GOOS=android GOARCH=arm64 go build -o libclient_android_arm64.so -buildmode=c-shared main.go
 2035  # command-line-arguments
 2036  loadinternal: cannot find runtime/cgo
 2037  /usr/local/go/pkg/tool/linux_amd64/link: running gcc failed: exit status 1
 2038  /usr/bin/ld: /tmp/go-link-1844065818/go.o: Relocations in generic ELF (EM: 183)
 2039  /usr/bin/ld: /tmp/go-link-1844065818/go.o: error adding symbols: file in wrong format
 2040  export ANDROID_NDK_HOME=/Documents/android-ndk-r26b
 2041  env CGO_ENABLED=1 GOOS=android GOARCH=arm64 GOARM=7 CC=/Documents/android-ndk-r26b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang go build -o libclient_android_arm64.so -buildmode=c-shared main.go
 2042  env CGO_ENABLED=1 GOOS=android GOARCH=arm64 GOARM=7 CC=Documents/android-ndk-r26b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang go build -o libclient_android_arm64.so -buildmode=c-shared main.go
 2043  env CGO_ENABLED=1 GOOS=android GOARCH=arm64 GOARM=7 CC=~/Documents/android-ndk-r26b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang go build -o libclient_android_arm64.so -buildmode=c-shared main.go
 2044  ldd libclient_android_arm64.so
 2045  ldd libclient_android_arm64
 2046  ldd libclient_android_arm64.so
 2047  ls
 2048  ldd libclient_amd64_x86_64.so
 2049  nm libclient_android_arm64.so | grep quicExecutable
 2050  nm libclient_amd64_x86_64.so | grep quicExecutable
 2051  ldd libclient_android_arm64
 2052  ldd libclient_android_arm64.so
 2053  file libclient_android_arm64.so
 2054  ldd libclient_android_arm64.so
 2055  history
*/