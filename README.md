## go-ice

Implementation of the ICE (Information Concealment Engine) encryption algorithm in Go.  
This is a port of the original C implementation written by [Matthew Kwan - July 1996](http://www.darkside.com.au/ice/).

## Installation

`go get github.com/akiver/go-ice`

## Usage

```go
import (
	"fmt"

	"github.com/akiver/go-ice/ice"
)

key := ice.NewIceKey(1)
key.Set([]byte{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89})

toEncrypt := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
encrypted := make([]byte, 8)
decrypted := make([]byte, 8)
key.Encrypt(toEncrypt, encrypted)
key.DecryptFullArray(encrypted, decrypted)

fmt.Println("To encrypt", toEncrypt)
fmt.Println("Encrypted", encrypted)
fmt.Println("Decrypted", decrypted)
// To encrypt [17 34 51 68 85 102 119 136]
// Encrypted [88 76 140 254 103 42 211 107]
// Decrypted [17 34 51 68 85 102 119 136]
```
