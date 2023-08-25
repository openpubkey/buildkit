package utils

import (
	"encoding/base64"

	"github.com/jonnystoten/openpubkey/types"
)

func Base64Encode(decoded []byte) types.Base64Encoded {
	encoding := base64.RawURLEncoding

	encoded := make([]byte, encoding.EncodedLen(len(decoded)))
	encoding.Encode(encoded, decoded)
	return encoded
}

func Base64Decode(encoded types.Base64Encoded) ([]byte, error) {
	encoding := base64.RawURLEncoding

	decoded := make([]byte, encoding.DecodedLen(len(encoded)))
	_, err := encoding.Decode(decoded, encoded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}
