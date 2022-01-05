package rippleTransaction

import (
	"fmt"
	"io"
)

type Reader interface {
	io.ByteScanner
	io.Reader
	Len() int
}

type LimitByteReader struct {
	R Reader // underlying reader
	N int64  // max bytes remaining
}

func LimitedByteReader(r Reader, n int64) *LimitByteReader {
	return &LimitByteReader{r, n}
}

func (l *LimitByteReader) Len() int {
	return int(l.N)
}

func NewVariableByteReader(r Reader) (Reader, error) {
	if length, err := readVariableLength(r); err != nil {
		return nil, err
	} else {
		return LimitedByteReader(r, int64(length)), nil
	}
}

func readVariableLength(r Reader) (int, error) {
	var first, second, third byte
	var err error
	if first, err = r.ReadByte(); err != nil {
		return 0, err
	}
	switch {
	case first <= 192:
		return int(first), nil
	case first <= 240:
		if second, err = r.ReadByte(); err != nil {
			return 0, nil
		}
		return 193 + int(first-193)*256 + int(second), nil
	case first <= 254:
		if second, err = r.ReadByte(); err != nil {
			return 0, nil
		}
		if third, err = r.ReadByte(); err != nil {
			return 0, nil
		}
		return 12481 + int(first-241)*65536 + int(second)*256 + int(third), nil
	}
	return 0, fmt.Errorf("Unsupported Variable Length encoding")
}

func (l *LimitByteReader) Read(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
	}
	n, err = l.R.Read(p)
	l.N -= int64(n)
	return
}

func (l *LimitByteReader) ReadByte() (c byte, err error) {
	if l.N <= 0 {
		return 0, io.EOF
	}
	l.N--
	return l.R.ReadByte()
}

func (l *LimitByteReader) UnreadByte() error {
	if err := l.UnreadByte(); err != nil {
		return err
	}
	l.N++
	return nil
}
func unmarshalSlice(s []byte, r Reader, prefix string) error {
	n, err := r.Read(s)
	if n != len(s) {
		return fmt.Errorf("%s: short read: %d expected: %d", prefix, n, len(s))
	}
	if err != nil {
		return fmt.Errorf("%s: %s", prefix, err.Error())
	}
	return nil
}