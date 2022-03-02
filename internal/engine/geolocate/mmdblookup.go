package geolocate

import "errors"

// LookupASN returns the ASN and the organization associated with the
// given IP address.
func LookupASN(ip string) (asn uint, org string, err error) {
	return 0, "", errors.New("not implemented")
}
