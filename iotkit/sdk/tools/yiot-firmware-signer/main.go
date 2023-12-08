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

package main

import (
	"fmt"
	"log"
	"os"

	"./utility"

	"gopkg.in/urfave/cli.v2"
)

var version = "0.1.0"

func main() {
	flags := []cli.Flag{
		&cli.PathFlag{
			Name:    "key",
			Aliases: []string{"k"},
			Usage:   "Path to a private key file",
		},
		&cli.PathFlag{
			Name:    "manifest",
			Aliases: []string{"m"},
			Usage:   "Path to a file with base manifest data",
		},
		&cli.PathFlag{
			Name:    "firmware",
			Aliases: []string{"f"},
			Usage:   "Firmware file",
		},
		&cli.PathFlag{
			Name:    "destination",
			Aliases: []string{"d"},
			Usage:   "Destivation folder",
		},
		&cli.StringFlag{
			Name:    "manufacturer",
			Aliases: []string{"n"},
			Usage:   "Device manufacturer",
		},
		&cli.StringFlag{
			Name:    "device",
			Aliases: []string{"c"},
			Usage:   "Device name",
		},
		&cli.StringFlag{
			Name:    "model",
			Aliases: []string{"l"},
			Usage:   "Device model",
		},
		&cli.StringFlag{
			Name:  "fw-version",
			Usage: "Firmware version ([0-255].[0-255].[0-255].[0-4294967295])",
		},
	}

	app := &cli.App{
		Name:    "yiot-firmware-signer",
		Usage:   "YIoT util for signing firmware",
		Version: version,
		Flags:   flags,
		Action: func(context *cli.Context) error {
			return signerFunc(context)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func checkFileParam(context *cli.Context, param string) (val string, err error) {
	var f string
	if f = context.Path(param); f == "" {
		return "", fmt.Errorf("--%s isn't specified", param)
	}
	if _, err = os.Stat(f); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("input file by given path %s doesn't exist", f)
		}
		return "", err
	}
	return f, nil
}

func signerFunc(context *cli.Context) (err error) {
	signerUtil := new(utility.SignerUtility)

	// Verify and set input parameters

	// --firmware
	f, err := checkFileParam(context, "firmware")
	if err != nil {
		return err
	}
	signerUtil.FirmwarePath = f

	// --key
	f, err = checkFileParam(context, "key")
	if err != nil {
		return err
	}
	signerUtil.PrivateKeyPath = f

	// --manifest
	f, err = checkFileParam(context, "manifest")
	if err != nil {
		return err
	}
	signerUtil.BaseManifestPath = f

	// --destination
	f, err = checkFileParam(context, "destination")
	if err != nil {
		return err
	}
	signerUtil.DestinationPath = f

	// --fw-version
	fwVersion := context.String("fw-version")
	if fwVersion == "" {
		return fmt.Errorf("--fw-version isn't specified")
	}
	signerUtil.FirmwareVersion = fwVersion

	// --manufacturer
	manufacturer := context.String("manufacturer")
	if manufacturer == "" {
		return fmt.Errorf("--manufacturer isn't specified")
	}
	signerUtil.Manufacturer = manufacturer

	// --device
	device := context.String("device")
	if device == "" {
		return fmt.Errorf("--device isn't specified")
	}
	signerUtil.Device = device

	// --model
	model := context.String("model")
	if model == "" {
		return fmt.Errorf("--model isn't specified")
	}
	signerUtil.Model = model

	// Sign
	err = signerUtil.CreateSignedFirmware()
	if err != nil {
		msg := fmt.Sprintf("Error during signed firmware creation: %v", err)
		return cli.Exit(msg, 1)
	}

	return nil
}
