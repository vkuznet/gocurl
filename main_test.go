package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_checkFile function
func Test_read(t *testing.T) {
	tmpFile, err := ioutil.TempFile(os.TempDir(), "gocurl-")
	defer os.Remove(tmpFile.Name())
	fname := tmpFile.Name()
	fmt.Println("Created File: " + fname)
	data := "gocurl-test"
	if _, err = tmpFile.Write([]byte(data)); err != nil {
		log.Fatalf("Unable to write, file: %s, error: %v\n", fname, err)
	}
	if err := tmpFile.Close(); err != nil {
		log.Fatal(err)
	}
	res := read("@" + fname)
	assert.Equal(t, res, data)
}
