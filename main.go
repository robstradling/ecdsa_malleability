package main

import (
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
)

var (
	in_filename = flag.String("i", "/dev/stdin", "Input certificate filename (format [DER, PEM] is auto-detected)")
	out_filename = flag.String("o", "/dev/stdout", "Output certificate filename (DER)")
	curve_name = flag.String("c", "P-256", "Elliptic curve name (P-256, P-384, P-521)")
)

type ecdsaSignature struct {
	R, S *big.Int
}

type certificate struct {
	TBSCertificate asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}


func main() {
	flag.Parse()

	// Read the input file.
	cert_data, err := os.ReadFile(*in_filename)
	if err != nil {
		panic(err)
	}

	// If needed, convert PEM input to DER.
	if cert_data[0] != 0x30 {
		if block, _ := pem.Decode(cert_data); block == nil {
			panic(fmt.Errorf("Failed to decode PEM block from certificate file"))
		} else {
			cert_data = block.Bytes
		}
	}

	// Parse a certificate from the input.
	cert, err := x509.ParseCertificate(cert_data)
	if err != nil {
		panic(err)
	}

	// Generate the certificate's signature algorithm OID.
	var sig_alg pkix.AlgorithmIdentifier
	switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA256: sig_alg = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
		case x509.ECDSAWithSHA384: sig_alg = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}}
		case x509.ECDSAWithSHA512: sig_alg = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}}
		default:
			panic(fmt.Errorf("Certificate does not have a supported ECDSA signature"))
	}

	// From the curve's parameters, get N (the order of the base point).
	var N *big.Int
	switch *curve_name {
		case "P-256": N = elliptic.P256().Params().N
		case "P-384": N = elliptic.P384().Params().N
		case "P-521": N = elliptic.P521().Params().N
		default: panic(fmt.Errorf("Unsupported curve"))
	}

	// Decode the ECDSA signature from the certificate.
	signature := &ecdsaSignature{}
	if _, err = asn1.Unmarshal(cert.Signature, signature); err != nil {
		panic(err)
	}

	// Produce -s (mod N).
	var minus_s big.Int
	minus_s.Neg(signature.S)
	signature.S.Mod(&minus_s, N)

	// Encode new certificate.
	new_cert := certificate{
		TBSCertificate: asn1.RawValue{FullBytes: cert.RawTBSCertificate},
		SignatureAlgorithm: sig_alg,
	}
	if new_cert.Signature.Bytes, err = asn1.Marshal(*signature); err != nil {
		panic(err)
	}

	// Write DER certificate to output file.
	if new_cert_data, err := asn1.Marshal(new_cert); err != nil {
		panic(err)
	} else {
		os.WriteFile(*out_filename, new_cert_data, 0666)
	}
}
