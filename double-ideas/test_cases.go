package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
)

func unhex(h string) []byte {
	b, _ := hex.DecodeString(h)
	return b
}

// Test cases:
// * No extensions
// * OHB
// * E2EEL + OHB
var (
	noExtOuterAADHex = "80010203deadbeeffeedface"
	noExtInnerAADHex = "80010203deadbeeffeedface"

	ohbOuterAADHex = "90010203deadbeeffeedface" +
		"bede0002" + // Extension header
		"107f23a0" + // OHB, HBH header
		"a1a2a300" // HBH header, padding
	ohbInnerAADHex = "807f0203deadbeeffeedface"

	e2eelOuterAADHex = "90010203deadbeeffeedface" +
		"bede0003" + // Extension header
		"110003" + // E2EEL
		"000000" + // E2E extension data
		"227faabb" + // OHB
		"0000" // Padding
	e2eelInnerAADHex = "907faabbdeadbeeffeedface" + "bede0002" + "110003" + "000000"
)

var (
	// 128 bit keys
	innerKeyHex = "482383ca8e4eb2eb86e03ed14c65bb81"
	outerKeyHex = "1ef806b01c412b2f69b2ec8c8da6de22"

	// 256 bit keys
	//innerKeyHex = "914808dcf7de7475d56714deea6a67d1f8349a84b30ebe829bb5e06a42694353"
	//outerKeyHex = "01edaea4a13801fa5e7d639cc16771a3c2da09d5c27af705e1a2d6adab2c7132"

	ivHex        = "1d2b9710540a78009c84d2d9"
	saltHex      = "0102030405060708090a0b0c"
	plaintextHex = "d9313225f88406e5a55909c5aff5269a86a7a953" +
		"1534f7da2e4c303d8a318a721c3c0c9595680953" +
		"2fcf0e2449a6b525b16aedf5aa0de657ba637b39"

	innerKey  = unhex(innerKeyHex)
	outerKey  = unhex(outerKeyHex)
	iv        = unhex(ivHex)
	salt      = unhex(saltHex)
	plaintext = unhex(plaintextHex)

	noExtInnerAAD = unhex(noExtInnerAADHex)
	noExtOuterAAD = unhex(noExtOuterAADHex)
	ohbInnerAAD   = unhex(ohbInnerAADHex)
	ohbOuterAAD   = unhex(ohbOuterAADHex)
	e2eelInnerAAD = unhex(e2eelInnerAADHex)
	e2eelOuterAAD = unhex(e2eelOuterAADHex)
)

func printVal(id int, label string, val []byte) {
	fmt.Printf("static const uint8_t srtp_aes_gcm_double_test_case_%d_%s[%d] = {", id, label, len(val))

	for i, b := range val {
		if i%8 == 0 {
			fmt.Printf("\n    ")
		}

		fmt.Printf("0x%02x, ", b)
	}

	fmt.Printf("\n};\n\n")
}

func main() {
	innerBlock, _ := aes.NewCipher(innerKey)
	innerCipher, _ := cipher.NewGCM(innerBlock)

	outerBlock, _ := aes.NewCipher(outerKey)
	outerCipher, _ := cipher.NewGCM(outerBlock)

	noExtInnerCT := innerCipher.Seal(nil, iv, plaintext, noExtInnerAAD)
	noExtOuterCT := outerCipher.Seal(nil, iv, noExtInnerCT, noExtOuterAAD)

	ohbInnerCT := innerCipher.Seal(nil, iv, plaintext, ohbInnerAAD)
	ohbOuterCT := outerCipher.Seal(nil, iv, ohbInnerCT, ohbOuterAAD)

	e2eelInnerCT := innerCipher.Seal(nil, iv, plaintext, e2eelInnerAAD)
	e2eelOuterCT := outerCipher.Seal(nil, iv, e2eelInnerCT, e2eelOuterAAD)

	totalKeyWSalt := append(innerKey, outerKey...)
	totalKeyWSalt = append(totalKeyWSalt, salt...)

	zero := make([]byte, len(innerKey))
	totalKeyWSalt0 := append(zero, outerKey...)
	totalKeyWSalt0 = append(totalKeyWSalt0, salt...)

	id := 0
	printVal(id, "key", totalKeyWSalt)
	printVal(id, "key_0", totalKeyWSalt0)
	printVal(id, "iv", iv)
	printVal(id, "plaintext", plaintext)
	printVal(id, "plaintext_0", noExtInnerCT)
	printVal(id, "aad_no_ext", noExtOuterAAD)
	printVal(id, "ciphertext", noExtOuterCT)

	/*** OHB case ***/
	printVal(id, "aad_ohb", ohbOuterAAD)
	printVal(id, "ciphertext_ohb", ohbOuterCT)

	/*** e2eel case ***/
	printVal(id, "aad_e2eel", e2eelOuterAAD)
	printVal(id, "ciphertext_e2eel", e2eelOuterCT)
}
