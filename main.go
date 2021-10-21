package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httputil"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/vkuznet/x509proxy"
)

type strFlags []string

func (i *strFlags) String() string {
	return "string flag"
}

func (i *strFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Request represents our http request
type Request struct {
	Url     string            // request url
	Method  string            // http method
	Data    string            // request data, e.g. json payload
	Headers map[string]string // request headers
	Forms   map[string]string // request forms
	Output  string            // output file name
	Key     string            // x509 key or proxy file name
	Cert    string            // x509 cert or proxy file name
	RootCA  string            // root CA file name
	Timeout int               // http client timeout
	Verbose int               // verbosity level
}

func main() {
	var verbose int
	flag.IntVar(&verbose, "verbose", 0, "verbosity level")
	flag.IntVar(&verbose, "v", 0, "alias for -verbose option")
	var data string
	flag.StringVar(&data, "data", "", "input data or data file")
	flag.StringVar(&data, "d", "", "alias for -data option")
	var header strFlags
	flag.Var(&header, "header", "HTTP header, e.g. Content-Type:application/json")
	flag.Var(&header, "h", "alias for -header option")
	var form strFlags
	flag.Var(&form, "form", "HTTP form key-value pair, e.g. key=value")
	flag.Var(&form, "f", "alias for -form option")
	var rurl string
	flag.StringVar(&rurl, "url", "", "input url")
	flag.StringVar(&rurl, "u", "", "alias for -url option")
	var method string
	flag.StringVar(&method, "method", "GET", "HTTP method")
	flag.StringVar(&method, "m", "GET", "alias for -method option")
	var key string
	flag.StringVar(&key, "key", "", "X509 key file name")
	flag.StringVar(&key, "k", "", "alias for -key option")
	var cert string
	flag.StringVar(&cert, "cert", "", "X509 cert file name")
	flag.StringVar(&cert, "c", "", "alias for -cert option")
	var rootCA string
	flag.StringVar(&rootCA, "rootCA", "", "rootCA file name")
	var fout string
	flag.StringVar(&fout, "out", "", "output file name")
	flag.StringVar(&fout, "o", "", "alias for -out option")
	var timeout int
	flag.IntVar(&timeout, "timeout", 0, "HTTP timeout value")
	flag.IntVar(&timeout, "t", 0, "alias -timeout option")
	flag.Parse()

	// set logger flags
	log.SetFlags(0)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if rurl == "" {
		log.Fatal("no input url")
	}

	// parse input header field
	hmap := make(map[string]string)
	for _, h := range header {
		h := strings.Trim(h, " ")
		arr := strings.Split(h, ":")
		if len(arr) != 2 {
			log.Fatal("fail to parse input HTTP header")
		}
		hmap[strings.Trim(arr[0], " ")] = strings.Trim(arr[1], " ")
	}
	if verbose > 0 {
		log.Println("HTTP headers")
		for k, v := range hmap {
			log.Println(k, v)
		}
	}

	// parse form pairs
	fmap := make(map[string]string)
	for _, f := range form {
		arr := strings.SplitN(f, "=", 2)
		if len(arr) != 2 {
			log.Fatal("fail to parse input form")
		}
		fmap[arr[0]] = arr[1]
	}
	if verbose > 0 {
		log.Println("HTTP form pairs")
		for k, v := range fmap {
			log.Println(k, v)
		}
	}

	// run actual request workflow
	req := Request{
		Url:     rurl,
		Method:  method,
		Data:    data,
		Headers: hmap,
		Forms:   fmap,
		Key:     key,
		Cert:    cert,
		RootCA:  rootCA,
		Timeout: timeout,
		Output:  fout,
		Verbose: verbose,
	}
	run(req)
}

// helper function to read given file or return data
func read(r string) string {
	if r == "" {
		return r
	}
	if strings.HasPrefix(r, "@") {
		fname := r[1:len(r)]
		if _, err := os.Stat(fname); err == nil {
			b, e := ioutil.ReadFile(fname)
			if e != nil {
				log.Fatalf("Unable to read data from file: %s, error: %s", r, e)
			}
			return string(b)
		}
	}
	return r
}

// client X509 certificates
func tlsCerts(key, cert string) ([]tls.Certificate, error) {
	uproxy := os.Getenv("X509_USER_PROXY")
	uckey := os.Getenv("X509_USER_KEY")
	ucert := os.Getenv("X509_USER_CERT")
	if key != "" {
		uckey = key
	}
	if cert != "" {
		ucert = cert
	}

	// check if /tmp/x509up_u$UID exists, if so setup X509_USER_PROXY env
	u, err := user.Current()
	if err == nil {
		fname := fmt.Sprintf("/tmp/x509up_u%s", u.Uid)
		if _, err := os.Stat(fname); err == nil {
			uproxy = fname
		}
	}

	if uproxy == "" && uckey == "" { // user doesn't have neither proxy or user certs
		return nil, nil
	}
	if uproxy != "" {
		// use local implementation of LoadX409KeyPair instead of tls one
		x509cert, err := x509proxy.LoadX509Proxy(uproxy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X509 proxy: %v", err)
		}
		certs := []tls.Certificate{x509cert}
		return certs, nil
	}
	x509cert, err := tls.LoadX509KeyPair(ucert, uckey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user X509 certificate: %v", err)
	}
	certs := []tls.Certificate{x509cert}
	return certs, nil
}

// HttpClient is HTTP client for urlfetch server
func HttpClient(key, cert, rootCA string, tout int) *http.Client {
	var certs []tls.Certificate
	var err error
	// get X509 certs
	certs, err = tlsCerts(key, cert)
	if err != nil {
		log.Fatal("ERROR ", err.Error())
	}
	timeout := time.Duration(tout) * time.Second
	if len(certs) == 0 {
		if tout > 0 {
			return &http.Client{Timeout: time.Duration(timeout)}
		}
		return &http.Client{}
	}
	var tr *http.Transport
	if rootCA != "" {
		caCert, err := ioutil.ReadFile(rootCA)
		if err != nil {
			log.Fatal("ERROR ", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       certs,
				RootCAs:            caCertPool,
				InsecureSkipVerify: true},
		}
	} else {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       certs,
				InsecureSkipVerify: true},
		}
	}
	if tout > 0 {
		return &http.Client{Transport: tr, Timeout: timeout}
	}
	return &http.Client{Transport: tr}
}

// func run(rurl, params string, headers, fmap map[string]string, fout string, tout, verbose int) {
func run(r Request) {
	client := HttpClient(r.Key, r.Cert, r.RootCA, r.Timeout)
	var req *http.Request
	if r.Method == "POST" {
		if len(r.Data) > 0 {
			args := read(r.Data)
			jsonStr := []byte(args)
			req, _ = http.NewRequest("POST", r.Url, bytes.NewBuffer(jsonStr))
			//         req.Header.Set("Content-Type", "application/json")
		} else if len(r.Forms) > 0 {
			// create multipart writer
			body := &bytes.Buffer{}
			var nbytes int64
			writer := multipart.NewWriter(body)
			// get keys of form map and place "file" key to be last
			var keys []string
			for k, _ := range r.Forms {
				if k == "file" {
					continue
				}
				keys = append(keys, k)
			}
			if _, ok := r.Forms["file"]; ok {
				keys = append(keys, "file")
			}
			//             for key, val := range r.Forms {
			for _, key := range keys {
				val, _ := r.Forms[key]
				if strings.HasPrefix(val, "@") {
					// if our key is a file name, we'll read and send it over
					fname := val[1:len(val)]
					arr := strings.Split(fname, "/")
					oname := arr[len(arr)-1]
					fw, err := writer.CreateFormFile(key, oname)
					if err != nil {
						log.Fatal(err)
					}
					file, err := os.Open(fname)
					if err != nil {
						log.Fatal(err)
					}
					nbytes, err = io.Copy(fw, file)
					if err != nil {
						log.Fatal(err)
					}
					if r.Verbose > 2 {
						log.Printf("read %d bytes from %s", nbytes, fname)
					}
				} else {
					// otherwise we'll use a form key-value pair
					fw, err := writer.CreateFormField(key)
					if err != nil {
						log.Fatal(err)
					}
					nbytes, err = io.Copy(fw, strings.NewReader(val))
					if err != nil {
						log.Fatal(err)
					}
					if r.Verbose > 2 {
						log.Printf("read %d bytes from %s=%s", nbytes, key, val)
					}
				}
			}
			writer.Close()

			req, _ = http.NewRequest("POST", r.Url, bytes.NewReader(body.Bytes()))
			req.Header.Set("Content-Type", writer.FormDataContentType())
		}
	} else if r.Method == "GET" {
		req, _ = http.NewRequest("GET", r.Url, nil)
	} else if r.Method == "PUT" {
		if len(r.Data) > 0 {
			args := read(r.Data)
			jsonStr := []byte(args)
			req, _ = http.NewRequest("PUT", r.Url, bytes.NewBuffer(jsonStr))
		}
	} else if r.Method == "DELETE" {
		req, _ = http.NewRequest("DELETE", r.Url, nil)
	} else {
		log.Fatal("Not implemented yet")
	}
	for key, val := range r.Headers {
		req.Header.Add(key, val)
	}
	if r.Verbose > 1 {
		dump, err := httputil.DumpRequestOut(req, true)
		log.Printf("http request %+v, url %v, dump %v, error %v\n", req, r.Url, string(dump), err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if r.Verbose > 1 {
		if resp != nil {
			dump, err := httputil.DumpResponse(resp, true)
			log.Printf("http response url %v, dump %v, error %v\n", r.Url, string(dump), err)
		}
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	if r.Output != "" {
		err := ioutil.WriteFile(r.Output, data, 0777)
		if err != nil {
			log.Fatalf("Unable to write, file: %s, error: %v\n", r.Output, err)
		}
	} else {
		fmt.Println(string(data))
	}
}
