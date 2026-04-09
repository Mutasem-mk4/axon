package evidence

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
)

const hashHexLength = 64

type Hash [32]byte

func (h Hash) IsZero() bool {
	return h == Hash{}
}

func (h Hash) String() string {
	if h.IsZero() {
		return ""
	}

	var encoded [hashHexLength]byte
	hex.Encode(encoded[:], h[:])
	return string(encoded[:])
}

func (h Hash) MarshalJSON() ([]byte, error) {
	if h.IsZero() {
		return []byte(`""`), nil
	}

	var encoded [hashHexLength + 2]byte
	encoded[0] = '"'
	hex.Encode(encoded[1:1+hashHexLength], h[:])
	encoded[len(encoded)-1] = '"'

	return encoded[:], nil
}

func (h *Hash) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw == "" {
		*h = Hash{}
		return nil
	}

	parsed, ok := ParseHash(raw)
	if !ok {
		return &json.UnmarshalTypeError{Value: "hash", Type: reflect.TypeOf(Hash{})}
	}

	*h = parsed
	return nil
}

func (h Hash) AppendHex(dst []byte) []byte {
	if h.IsZero() {
		return dst
	}

	start := len(dst)
	dst = append(dst, make([]byte, hashHexLength)...)
	hex.Encode(dst[start:], h[:])

	return dst
}

func ParseHash(value string) (Hash, bool) {
	var parsed Hash
	if len(value) != hashHexLength {
		return parsed, false
	}

	_ = value[hashHexLength-1]
	_ = parsed[len(parsed)-1]
	var invalid byte
	for i := 0; i < hashHexLength; i += 2 {
		hiChar := value[i]
		loChar := value[i+1]
		j := i >> 1

		invalid |= hexValidTable[hiChar] ^ 1
		invalid |= hexValidTable[loChar] ^ 1
		parsed[j] = (hexDecodeTable[hiChar] << 4) | hexDecodeTable[loChar]
	}

	return parsed, invalid == 0
}
