# keyAndCert
Generate Private Key and Self Signed Cert

go run main.go generates key.pem and cert.pem and prints output

to verify:
openssl x509 -modulus -noout -in cert.pem| openssl md5
openssl rsa -modulus -noout -in key.pem | openssl md5
