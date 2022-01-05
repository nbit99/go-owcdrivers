package rippleTransaction
import (
	"fmt"
	"strings"
)

type Asset struct {
	Currency string `json:"currency"`
	Issuer   string `json:"issuer,omitempty"`
}

func NewAsset(s string) (*Asset, error) {
	if s == "XRP" {
		return &Asset{
			Currency: s,
		}, nil
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("bad asset: %s", s)
	}
	return &Asset{
		Currency: parts[0],
		Issuer:   parts[1],
	}, nil
}

func (a *Asset) IsNative() bool {
	return a.Currency == "XRP"
}

func (a *Asset) Matches(amount *Amount) bool {
	return (a.IsNative() && amount.IsNative()) ||
		(a.Currency == amount.Currency.String() && a.Issuer == amount.Issuer.String())
}

func (a Asset) String() string {
	if a.IsNative() {
		return a.Currency
	}
	return fmt.Sprintf("%s/%s", a.Currency, a.Issuer)
}
