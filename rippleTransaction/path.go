package rippleTransaction

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
)

type pathEntry uint8

const (
	PATH_BOUNDARY pathEntry = 0xFF
	PATH_END      pathEntry = 0x00

	PATH_ACCOUNT  pathEntry = 0x01
	PATH_REDEEM   pathEntry = 0x02
	PATH_CURRENCY pathEntry = 0x10
	PATH_ISSUER   pathEntry = 0x20
)

// PathElem represents one link in a path.
type PathElem struct {
	Account  *Account
	Currency *Currency
	Issuer   *Account
}

func newPathElem(s string) (PathElem, error) {
	var err error
	pe := PathElem{}

	parts := strings.Split(s, "/")
	switch {
	case len(parts) == 1:
		pe.Account, err = NewAccountFromAddress(parts[0])
		if err != nil {
			return pe, err
		}

	case len(parts) == 2:
		pe.Currency = &Currency{}
		*pe.Currency, err = NewCurrency(parts[0])
		if err != nil {
			return pe, err
		}

		pe.Issuer, err = NewAccountFromAddress(parts[1])
		if err != nil {
			return pe, err
		}

	default:
		return pe, fmt.Errorf("Bad PathElem: %s", s)
	}
	return pe, nil
}

// Path represents a single path of liquidity that a transaction may use.
type Path []PathElem

// NewPath accepts a path consisting of hops delimited by "=>" where each hop
// is either "<currency>/<issuer>" or "<account>". Whitespace around the delimiter
// is acceptable and is ignored.
func NewPath(s string) (Path, error) {
	p := Path{}
	for _, part := range strings.Split(s, "=>") {
		pe, err := newPathElem(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		p = append(p, pe)
	}
	return p, nil
}

// PathSet represents a collection of possible paths that a transaction may use.
type PathSet []Path

func (p PathElem) pathEntry() pathEntry {
	var entry pathEntry
	if p.Account != nil {
		entry |= PATH_ACCOUNT
	}
	if p.Currency != nil {
		entry |= PATH_CURRENCY
	}
	if p.Issuer != nil {
		entry |= PATH_ISSUER
	}
	return entry
}

func (p Path) Signature() (uint32, error) {
	checksum := crc32.NewIEEE()
	for _, path := range p {
		b := append(path.Account.Bytes(), append(path.Currency.Bytes(), path.Issuer.Bytes()...)...)
		if _, err := checksum.Write(b); err != nil {
			return 0, err
		}
	}
	return checksum.Sum32(), nil
}

func (p Path) String() string {
	var s []string
	for _, path := range p {
		s = append(s, path.String())
	}
	return strings.Join(s, " => ")
}

func (p PathElem) String() string {
	var s []string
	if p.Account != nil {
		s = append(s, p.Account.String())
	}
	if p.Currency != nil {
		s = append(s, p.Currency.String())
	}
	if p.Issuer != nil {
		s = append(s, p.Issuer.String())
	}
	return strings.Join(s, "/")
}

func (p PathElem) MarshalJSON() ([]byte, error) {
	typ := p.pathEntry()
	return json.Marshal(struct {
		Account  *Account  `json:"account,omitempty"`
		Currency *Currency `json:"currency,omitempty"`
		Issuer   *Account  `json:"issuer,omitempty"`
		Type     pathEntry `json:"type"`
		TypeHex  string    `json:"type_hex"`
	}{
		p.Account,
		p.Currency,
		p.Issuer,
		typ,
		fmt.Sprintf("%016X", uint64(typ)),
	})
}


func (p *PathSet) Unmarshal(r Reader) error {
	for i := 0; ; i++ {
		*p = append(*p, Path{})
		for b, err := r.ReadByte(); ; b, err = r.ReadByte() {
			entry := pathEntry(b)
			if entry == PATH_BOUNDARY {
				break
			}
			if err != nil {
				return err
			}
			if entry == PATH_END {
				return nil
			}
			var pe PathElem
			if entry&PATH_ACCOUNT > 0 {
				pe.Account = new(Account)
				if _, err := r.Read(pe.Account.Bytes()); err != nil {
					return err
				}
			}
			if entry&PATH_CURRENCY > 0 {
				pe.Currency = new(Currency)
				if _, err := r.Read(pe.Currency.Bytes()); err != nil {
					return err
				}
			}
			if entry&PATH_ISSUER > 0 {
				pe.Issuer = new(Account)
				if _, err := r.Read(pe.Issuer.Bytes()); err != nil {
					return err
				}
			}
			(*p)[i] = append((*p)[i], pe)
		}
	}
}

func (p *PathSet) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	w := io.Writer(buf)
	for i, path := range *p {
		for _, entry := range path {
			if err := write(w, entry.pathEntry()); err != nil {
				return nil, err
			}
			if err := write(w, entry.Account.Bytes()); err != nil {
				return nil, err
			}
			if err := write(w, entry.Currency.Bytes()); err != nil {
				return nil, err
			}
			if err := write(w, entry.Issuer.Bytes()); err != nil {
				return nil, err
			}
		}
		var err error
		if i < len(*p)-1 {
			err = write(w, PATH_BOUNDARY)
		} else {
			err = write(w, PATH_END)
		}
		if err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func write(w io.Writer, v interface{}) error {
	return binary.Write(w, binary.BigEndian, v)
}