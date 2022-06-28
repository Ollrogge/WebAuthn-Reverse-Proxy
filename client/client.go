package client

import (
	"errors"
	"log"

	libfido2 "fido2proxy/fido2"
)

func DeviceAssertion(rpID string, clientDataHash []byte,
	credentialIDs [][]byte) (*libfido2.Assertion, error) {
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return nil, err
	}
	if len(locs) == 0 {
		log.Println("No devices")
		return nil, errors.New("No devices found")
	}

	log.Printf("Using device: %+v\n", locs[0])
	path := locs[0].Path
	device, err := libfido2.NewDevice(path)
	if err != nil {
		return nil, err
	}

	assertion, err := device.Assertion(rpID, clientDataHash, credentialIDs,
		"", nil)

	if err != nil {
		return nil, err
	}

	log.Println("Assertion: ", assertion)

	return assertion, nil
}
