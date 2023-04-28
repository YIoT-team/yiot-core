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

package utility

import (
	"bufio"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"time"

	"../firmware"
	"../signers"
)

// ----------------------------------------------------------------------------
//
// Manifest structure
//
type YIoTManifest struct {
	Manufacturer string                 `json:"manufacturer"`
	Device       string                 `json:"device"`
	Model        string                 `json:"model"`
	Version      string                 `json:"version"`
	Timestamp    int64                  `json:"timestamp"`
	Firmware     string                 `json:"firmware"`
	Signature    string                 `json:"signature"`
	ExtaraData   map[string]interface{} `json:"extra_data"`
}

// ----------------------------------------------------------------------------
//
// Signed Manifest structure
//
type YIoTSignedManifest struct {
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
}

type SignerUtility struct {
	PrivateKeyPath   string
	BaseManifestPath string
	DestinationPath  string
	FirmwarePath     string
	FirmwareVersion  string
	Manufacturer     string
	Device           string
	Model            string

	progFile *firmware.ProgFile
}

func _readFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)

	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		return nil, statsErr
	}

	var size int64 = stats.Size()
	bytes := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(bytes)

	return bytes, err
}

func (s *SignerUtility) CreateSignedFirmware() (err error) {

	// Read firmware data
	d, err := _readFile(s.FirmwarePath)
	if err != nil {
		return fmt.Errorf("Cannot read %s", s.FirmwarePath)
	}

	// Sign firmware
	sign, err := signers.Sign(d, s.PrivateKeyPath)
	if err != nil {
		return err
	}

	// Prepare a new firmware name
	name := fmt.Sprintf("%s-%s-%s-%s-%s", s.Manufacturer, s.Device, s.Model, s.FirmwareVersion, path.Base(s.FirmwarePath))

	// Read Base manifest
	bm, err := _readFile(s.BaseManifestPath)
	if err != nil {
		return fmt.Errorf("Cannot read %s", s.BaseManifestPath)
	}
	var bmMap map[string]interface{}
	if err := json.Unmarshal(bm, &bmMap); err != nil {
		return err
	}

	// Prepare manifest
	manifest := YIoTManifest{
		Manufacturer: s.Manufacturer,
		Device:       s.Device,
		Model:        s.Model,
		Version:      s.FirmwareVersion,
		Timestamp:    time.Now().Unix(),
		Firmware:     name,
		Signature:    b64.StdEncoding.EncodeToString(sign),
		ExtaraData:   bmMap,
	}

	// Internal manifest data
	m, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	internalManifest := string(m)
	println(internalManifest)
	internalManifestBase64 := b64.StdEncoding.EncodeToString([]byte(internalManifest))

	// Sign manifest
	signManifest, err := signers.Sign([]byte(internalManifestBase64), s.PrivateKeyPath)
	if err != nil {
		return err
	}

	// Prepare signed manifest
	signedManifest := YIoTSignedManifest{
		Manifest:  internalManifestBase64,
		Signature: b64.StdEncoding.EncodeToString([]byte(signManifest)),
	}

	// Signed manifest data
	sm, err := json.Marshal(signedManifest)
	if err != nil {
		return err
	}
	signedManifestStr := string(sm)
	println(signedManifestStr)

	// Create folders structure
	dstPath := path.Join(s.DestinationPath, s.Manufacturer, s.Device, s.Model, s.FirmwareVersion)
	os.MkdirAll(dstPath, os.ModePerm)

	// Copy firmware binary
	dstFirmware := path.Join(dstPath, name)
	cpCmd := exec.Command("cp", "-f", s.FirmwarePath, dstFirmware)
	err = cpCmd.Run()
	if err != nil {
		return fmt.Errorf("Cannot copy firmware file %s -> %s", s.FirmwarePath, dstFirmware)
	}

	// Save Signed manifest
	dstManifest := path.Join(dstPath, "manifest.json")
	err = ioutil.WriteFile(dstManifest, sm, 0644)
	if err != nil {
		return fmt.Errorf("Cannot save manifest %s", dstManifest)
	}

	return nil
}
