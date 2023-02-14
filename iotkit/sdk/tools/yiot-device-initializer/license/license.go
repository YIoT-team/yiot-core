//  ────────────────────────────────────────────────────────────
//                     ╔╗  ╔╗ ╔══╗      ╔════╗
//                     ║╚╗╔╝║ ╚╣╠╝      ║╔╗╔╗║
//                     ╚╗╚╝╔╝  ║║  ╔══╗ ╚╝║║╚╝
//                      ╚╗╔╝   ║║  ║╔╗║   ║║
//                       ║║   ╔╣╠╗ ║╚╝║   ║║
//                       ╚╝   ╚══╝ ╚══╝   ╚╝
//    ╔╗╔═╗                    ╔╗                     ╔╗
//    ║║║╔╝                   ╔╝╚╗                    ║║
//    ║╚╝╝  ╔══╗ ╔══╗ ╔══╗  ╔╗╚╗╔╝  ╔══╗ ╔╗ ╔╗╔╗ ╔══╗ ║║  ╔══╗
//    ║╔╗║  ║║═╣ ║║═╣ ║╔╗║  ╠╣ ║║   ║ ═╣ ╠╣ ║╚╝║ ║╔╗║ ║║  ║║═╣
//    ║║║╚╗ ║║═╣ ║║═╣ ║╚╝║  ║║ ║╚╗  ╠═ ║ ║║ ║║║║ ║╚╝║ ║╚╗ ║║═╣
//    ╚╝╚═╝ ╚══╝ ╚══╝ ║╔═╝  ╚╝ ╚═╝  ╚══╝ ╚╝ ╚╩╩╝ ║╔═╝ ╚═╝ ╚══╝
//                    ║║                         ║║
//                    ╚╝                         ╚╝
//
//    Lead Maintainer: Roman Kutashenko <kutashenko@gmail.com>
//  ────────────────────────────────────────────────────────────

package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"../common"
	//     "../converters"
	"../snap"
)

type Builder struct {
	Signer          common.SignerInterface
	DeviceProcessor *snap.DeviceProcessor
	LicenseData     interface{}

	deviceInfo *DeviceInfoJson
}

type DeviceInfoJson struct {
	Manufacturer  string   `json:"manufacturer"`
	Model         string   `json:"model"`
	Roles         []string `json:"roles"`
	Mac           string   `json:"mac"`
	Serial        []byte   `json:"serial"`
	PublicKeyTiny []byte   `json:"publicKeyTiny"`
	Signature     []byte   `json:"signature"`
	KeyType       uint8    `json:"key_type"`
	ECType        uint8    `json:"ec_type"`
}

type LicenseJson struct {
	TimeStamp int64          `json:"timestamp"`
	Device    DeviceInfoJson `json:"device"`
	ExtraData interface{}    `json:"data"`
}

type SignedLicenseJson struct {
	License   string `json:"license"`
	Signature string `json:"signature"`
}

func (b Builder) Build() (string, error) {

	// Fill License data
	lic := LicenseJson{
		TimeStamp: time.Now().Unix(),
		Device:    *b.deviceInfoData(),
		ExtraData: b.LicenseData,
	}

	// Prepare License Base64
	j, err := json.Marshal(lic)
	if err != nil {
		return "", fmt.Errorf("failed to marshal License: %v", err)
	}
	fmt.Printf("License : %v\n", string(j))
	b64Lic := base64.StdEncoding.EncodeToString(j)

	// Sign license
	virgilSignature, err := b.Signer.Sign([]byte(b64Lic))
	if err != nil {
		return "", err
	}
	if len(virgilSignature) == 0 {
		return "", fmt.Errorf("signature is empty")
	}

	// Prepare Signature in Base64 format
	b64Signature := base64.StdEncoding.EncodeToString(virgilSignature)

	// Signed license structure
	signedLic := SignedLicenseJson{
		License:   b64Lic,
		Signature: b64Signature,
	}

	// Prepare result
	l, err := json.Marshal(signedLic)
	if err != nil {
		return "", err
	}

	return string(l), nil
}

func (b *Builder) deviceInfoData() *DeviceInfoJson {
	mac := b.DeviceProcessor.DeviceMacAddr
	manufacturer := bytes.Trim(b.DeviceProcessor.Manufacturer[:], "\u0000")
	return &DeviceInfoJson{
		Manufacturer:  string(manufacturer),
		Model:         fmt.Sprintf("%#x", b.DeviceProcessor.Model),
		Mac:           fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]),
		Serial:        b.DeviceProcessor.Serial[:],
		PublicKeyTiny: b.DeviceProcessor.DevicePublicKey.PubKey.RawPubKey,
		Signature:     b.DeviceProcessor.Signature.RawSignature,
		KeyType:       b.DeviceProcessor.DevicePublicKey.PubKey.KeyType,
		ECType:        b.DeviceProcessor.DevicePublicKey.PubKey.ECType,
		Roles:         b.DeviceProcessor.Roles,
	}
}

func (b *Builder) GetDeviceInfo() ([]byte, error) {
	b.deviceInfo = b.deviceInfoData()
	marshaled, err := json.Marshal(b.deviceInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DeviceInfoJson: %v", err)
	}
	return marshaled, nil
}
