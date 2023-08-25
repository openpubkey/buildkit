package utils

import (
	"encoding/json"

	"github.com/jonnystoten/openpubkey/types"
)

func JSONMarshal(value any) (encoded types.JSON, err error) {
	encoded, err = json.Marshal(value)
	return
}

func JSONUnmarshal(encoded types.JSON) (value any, err error) {
	err = json.Unmarshal(encoded, &value)
	return
}
