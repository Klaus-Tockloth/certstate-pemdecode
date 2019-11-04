# certstate-pemdecode

## Purpose

'certstate-pemdecode' is a companion utility for 'certstate'. If 'certstate' is used with the '-verbose' option, the output
includes PEM-formatted certificates, OCSP responses and CRLs. 'certstate-pemdecode' expands the PEM-formatted sections into
plain text. OpenSSL is called to achieve this.

## Usage

```txt
$ ./certstate-pemdecode

Program:
  Name    : ./certstate-pemdecode
  Release : v0.2.0 - 2019/11/04
  Purpose : PEM decode
  Info    : Decodes PEM-formatted certstate output.

Error:
  File argument required.

Usage:
  ./certstate-pemdecode file

Examples:
  ./certstate-pemdecode certstate.out

Argument:
  file
        certstate output file with PEM-formatted (verbose) data objects

OpenSSL output commands:
  Certificate   : openssl x509 -certopt ext_dump -text -noout -inform PEM -in tempfile
  OCSP response : openssl ocsp -text -noverify -respin tempfile
  CRL           : openssl crl -text -noout -inform PEM -in tempfile
```

## Remarks

The master branch is used for program development and may be unstable. See 'Releases' for pre-build binaries.

## Build (master)

go get github.com/Klaus-Tockloth/certstate-pemdecode

make

## Links

github.com/Klaus-Tockloth/certstate

## Releases

### v0.1.0, 2018/10/01

- initial release

### v0.2.0, 2019/11/04 (pre-release)

- CRL support added
