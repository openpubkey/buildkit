package types

type JSON []byte

// func (b *JSON) MarshalText() ([]byte, error) {
// 	return *b, nil
// }

// Base64Encoded is a []byte which implements encoding.TextMarshaler
// and encoding.TextUnmarshaler to return itself. This is because json.Marshal
// usually base64-encodes values of []byte, which results in a double-encoding.
type Base64Encoded []byte

func (b *Base64Encoded) MarshalText() ([]byte, error) {
	return *b, nil
}

func (b *Base64Encoded) UnmarshalText(text []byte) error {
	*b = make(Base64Encoded, len(text))
	copy(*b, text)
	return nil
}
