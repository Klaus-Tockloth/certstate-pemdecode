# certstate-pemdecode

## Purpose

'certstate-pemdecode' is a companion utility if the 'certstate' tool is used with the '-verbose' option. The "-verbose" option
results in output including PEM-formatted certificates and OCSP responses. 'certstate-pemdecode' expands the PEM-formatted
sections into plain text. OpenSSL is called to achieve this.

## Usage

```txt
$ ./certstate-pemdecode 

Program:
  Name    : ./certstate-pemdecode
  Release : 0.1.0 - 2018/10/01
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
        certstate output file with PEM-formatted  (verbose) data objects

OpenSSL output commands:
  Certificate   : openssl x509 -certopt ext_dump -text -noout -inform PEM -in tempfile
  OCSP response : openssl ocsp -text -noverify -respin tempfile
```

## Remarks

The master branch is used for program development and may be unstable.

## Releases

### 0.1.0, 2018/10/01

- initial release
