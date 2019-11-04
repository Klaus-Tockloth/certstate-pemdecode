/*
Purpose:
- PEM decode

Description:
- Decodes PEM-formatted certstate output.

Releases:
- v0.1.0 - 2018/10/01 : initial release
- v0.2.0 - 2019/11/04 : CRL support added

Author:
- Klaus Tockloth

Copyright and license:
- Copyright (c) 2018, 2019 Klaus Tockloth
- MIT license

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the Software), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

The software is provided 'as is', without warranty of any kind, express or implied, including
but not limited to the warranties of merchantability, fitness for a particular purpose and
noninfringement. In no event shall the authors or copyright holders be liable for any claim,
damages or other liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in the software.

Contact (eMail):
- freizeitkarte@googlemail.com

Remarks:
- NN

Links:
- https://github.com/Klaus-Tockloth/certstate
*/

package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// general program info
var (
	progName    = os.Args[0]
	progVersion = "v0.2.0"
	progDate    = "2019/11/04"
	progPurpose = "PEM decode"
	progInfo    = "Decodes PEM-formatted certstate output."
)

// Testmode control extended outout for development
var Testmode = false

// separator between sections
var separator = "\n------------------------------------------------------------------------------------------------------------\n"

// openssl command lines
var (
	opensslCertificate = "openssl x509 -certopt ext_dump -text -noout -inform PEM -in %s"
	opensslOCSPResonse = "openssl ocsp -text -noverify -respin %s"
	opensslCRL         = "openssl crl -text -noout -inform PEM -in %s"
)

/*
init initializes this program
*/
func init() {

	// initialize logger
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
}

/*
main starts this program
*/
func main() {

	fmt.Printf("\nProgram:\n")
	fmt.Printf("  Name    : %s\n", progName)
	fmt.Printf("  Release : %s - %s\n", progVersion, progDate)
	fmt.Printf("  Purpose : %s\n", progPurpose)
	fmt.Printf("  Info    : %s\n", progInfo)

	// one file argument required
	if len(os.Args) != 2 {
		fmt.Printf("\nError:\n  File argument required.\n")
		printUsage()
	}

	inputFile := os.Args[1]

	fmt.Printf("\nProcessing:\n")
	fmt.Printf("  Input File         : %s\n", inputFile)
	fmt.Printf("  Output Certificate : %s\n", fmt.Sprintf(opensslCertificate, "tempfile"))
	fmt.Printf("  Output OCSPResonse : %s\n", fmt.Sprintf(opensslOCSPResonse, "tempfile"))
	fmt.Printf("  Output CRL         : %s\n", fmt.Sprintf(opensslCRL, "tempfile"))

	// read file into []byte
	pemContent, err := ioutil.ReadFile(inputFile)
	if err != nil {
		log.Fatalf("error <%v> at ioutil.ReadFile(); filename = <%v>", err, inputFile)
	}

	fmt.Printf("%sUnmodified data from file %q ...%s", separator, inputFile, separator)
	fmt.Printf("\n%s", string(pemContent))

	fmt.Printf("%sPEM blocks in textual form (openssl output) ...%s\n", separator, separator)

	// decode first PEM block
	pemBlock, rest := pem.Decode(pemContent)
	if pemBlock == nil {
		log.Fatal("failed to decode PEM block containing public key certificate")
	}
	printPEM(pemBlock)

	// decode following PEM blocks
	for pemBlock != nil {
		pemBlock, rest = pem.Decode(rest)
		if pemBlock == nil {
			break
		}
		printPEM(pemBlock)
	}

	fmt.Printf("\n")
	os.Exit(0)
}

/*
printUsage prints the usage of this program
*/
func printUsage() {

	fmt.Printf("\nUsage:\n")
	fmt.Printf("  %s file\n", os.Args[0])

	fmt.Printf("\nExamples:\n")
	fmt.Printf("  %s certstate.out\n", os.Args[0])

	fmt.Printf("\nArgument:\n")
	fmt.Printf("  file\n")
	fmt.Printf("        certstate output file with PEM-formatted (verbose) data objects\n")

	fmt.Printf("\nOpenSSL output commands:\n"+
		"  Certificate   : %s\n"+
		"  OCSP response : %s\n"+
		"  CRL           : %s\n",
		fmt.Sprintf(opensslCertificate, "tempfile"), fmt.Sprintf(opensslOCSPResonse, "tempfile"), fmt.Sprintf(opensslCRL, "tempfile"))

	fmt.Printf("\n")
	os.Exit(1)
}

/*
printPEM prints a single PEM data block
*/
func printPEM(pemBlock *pem.Block) {

	switch pemBlock.Type {
	case "CERTIFICATE":
		printCertificatePEM(pemBlock)
	case "OCSP RESPONSE":
		printOCSPResponsePEM(pemBlock)
	case "X509 CRL":
		printCRLPEM(pemBlock)
	default:
		fmt.Printf("\nPEM type <%v> not supported.\n", pemBlock.Type)
	}
}

/*
printCertificatePEM prints a single PEM data block
*/
func printCertificatePEM(pemBlock *pem.Block) {

	// encode PEM data again into PEM format
	var pemCertificate bytes.Buffer
	if err := pem.Encode(&pemCertificate, pemBlock); err != nil {
		log.Fatalf("error <%v> at pem.Encode()", err)
	}
	fmt.Printf("%s\n", pemCertificate.String())

	tmpfile, err := ioutil.TempFile("", "Certificate_PEM_Tempfile_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(pemCertificate.String())); err != nil {
		log.Fatalf("error <%v> at tmpfile.Write(); file = <%v>", err, tmpfile.Name())
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatalf("error <%v> at tmpfile.Close(); file = <%v>", err, tmpfile.Name())
	}

	// decode PEM data into TEXT format
	command := fmt.Sprintf(opensslCertificate, tmpfile.Name())
	_, commandOutput, err := runCommand(command)
	if err != nil {
		log.Printf("error <%v> at runCommand()", err)
	}
	fmt.Printf("%s\n", string(commandOutput))
}

/*
printOCSPResponsePEM prints a single PEM data block
*/
func printOCSPResponsePEM(pemBlock *pem.Block) {

	// encode PEM data again into PEM format
	var pemResponse bytes.Buffer
	if err := pem.Encode(&pemResponse, pemBlock); err != nil {
		log.Fatalf("error <%v> at pem.Encode()", err)
	}
	fmt.Printf("%s\n", pemResponse.String())

	tmpfile, err := ioutil.TempFile("", "OCSPResponse_DER_Tempfile_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(pemBlock.Bytes); err != nil {
		log.Fatalf("error <%v> at tmpfile.Write(); file = <%v>", err, tmpfile.Name())
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatalf("error <%v> at tmpfile.Close(); file = <%v>", err, tmpfile.Name())
	}

	// decode DER data into TEXT format
	command := fmt.Sprintf(opensslOCSPResonse, tmpfile.Name())
	_, commandOutput, err := runCommand(command)
	if err != nil {
		log.Printf("error <%v> at runCommand()", err)
	}
	fmt.Printf("%s\n", string(commandOutput))
}

/*
printCRLPEM prints a single PEM data block
*/
func printCRLPEM(pemBlock *pem.Block) {

	// encode PEM data again into PEM format
	var pemCertificate bytes.Buffer
	if err := pem.Encode(&pemCertificate, pemBlock); err != nil {
		log.Fatalf("error <%v> at pem.Encode()", err)
	}
	fmt.Printf("%s\n", pemCertificate.String())

	tmpfile, err := ioutil.TempFile("", "CRL_PEM_Tempfile_")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(pemCertificate.String())); err != nil {
		log.Fatalf("error <%v> at tmpfile.Write(); file = <%v>", err, tmpfile.Name())
	}
	if err := tmpfile.Close(); err != nil {
		log.Fatalf("error <%v> at tmpfile.Close(); file = <%v>", err, tmpfile.Name())
	}

	// decode PEM data into TEXT format
	command := fmt.Sprintf(opensslCRL, tmpfile.Name())
	_, commandOutput, err := runCommand(command)
	if err != nil {
		log.Printf("error <%v> at runCommand()", err)
	}
	fmt.Printf("%s\n", string(commandOutput))
}

/*
runCommand runs a command / program
*/
func runCommand(command string) (commandExitStatus int, commandOutput []byte, err error) {

	program := "/bin/bash"
	args := []string{"-c", command}
	cmd := exec.Command(program, args...)

	commandOutput, err = cmd.CombinedOutput()

	var waitStatus syscall.WaitStatus
	if err != nil {
		// command was not successful
		if exitError, ok := err.(*exec.ExitError); ok {
			// command fails because of an unsuccessful exit code
			waitStatus = exitError.Sys().(syscall.WaitStatus)
			log.Printf("command exit code = <%d>", waitStatus.ExitStatus())
		}
		log.Printf("error <%v> at cmd.CombinedOutput()", err)
		log.Printf("command (not successful) = <%s>", strings.Join(cmd.Args, " "))
		if len(commandOutput) > 0 {
			log.Printf("command output (stdout, stderr) =\n%s", string(commandOutput))
		}
	} else {
		// command was successful
		waitStatus = cmd.ProcessState.Sys().(syscall.WaitStatus)
		if Testmode {
			log.Printf("command (successful) = <%s>", strings.Join(cmd.Args, " "))
			log.Printf("command exit code = <%d>", waitStatus.ExitStatus())
			if len(commandOutput) > 0 {
				log.Printf("command output (stdout, stderr) =\n%s", string(commandOutput))
			}
		}
	}

	commandExitStatus = waitStatus.ExitStatus()
	return
}
