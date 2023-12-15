package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"sync"
	"time"
)

type keyId int

const (
	key = keyId(33)
)

type seed struct {
	seeder seeder
}

type seeder interface {
	GenerateCertTemplate(ctx context.Context) *x509.Certificate
	GetSerialNumber() uint64
}

func (s *seed) GetSerialNumber() uint64 {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("cannot seed math/rand package with cryptographically secure random number generator")
	}
	se := int64(binary.LittleEndian.Uint64(b[:]))
	m := big.NewInt(se).Exp(big.NewInt(2), big.NewInt(130), nil)
	mrand.New(mrand.NewSource(se)).Seed(se)
	n, err := rand.Int(rand.Reader, m)
	if err != nil {
		panic(err)
	}

	return n.Uint64()
}

func (s *seed) GenerateCertTemplate(ctx context.Context, wg *sync.WaitGroup) (
	error,
	*x509.Certificate,
) {

	log.Println("running goroutine to generate cert from private key")
	sn, ok := ctx.Value(key).(*big.Int)
	if !ok {
		log.Fatalf("failed to type assert the variable type: %v", sn)
	}

	x509t := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "com.apple.idms.appleid.test",
			Organization: []string{""},
			Country:      []string{""},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		IsCA:      ok,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		BasicConstraintsValid: ok,
		IPAddresses:           []net.IP{net.ParseIP("172.20.10.2"), net.ParseIP("127.0.0.1")},
	}
	//log.Println(&x509t)
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("failed to generate private key, error: %v", err)
	}
	go printPrivKey(ctx, privKey, wg)

	certBytes, err := x509.CreateCertificate(rand.Reader, &x509t, &x509t, &privKey.PublicKey, privKey)
	if err != nil {
		log.Fatalf("failed to create cert, error: %v", err)
	}
	go printCert(ctx, certBytes, wg)
	//ctxChan := make(chan context.Context)
	return nil, &x509t
}

func printPrivKey(ctx context.Context, pkey *rsa.PrivateKey, wg *sync.WaitGroup) {
	defer wg.Done()
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pkey),
	})
	f, err := os.Create("key.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)
	if _, err := f.Write(pemBytes); err != nil {
		panic(err)
	}

	log.Printf("key generated:\n %s", fmt.Sprint(string(pemBytes)))
}

func printCert(ctx context.Context, certBytes []byte, wg *sync.WaitGroup) {
	defer wg.Done()
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	f, err := os.Create("cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)
	if _, err := f.Write(pemBytes); err != nil {
		panic(err)
	}
	log.Printf("cert generated:\n %s", fmt.Sprint(string(pemBytes)))

	os.Exit(0)
}

func main() {
	//ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(1*time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Println("here")
	s := &seed{}
	time.Sleep(1 * time.Second)
	sn := new(big.Int).SetUint64(s.GetSerialNumber())
	//log.Printf("serial number is: %d", sn)
	ctx = context.WithValue(ctx, key, sn)
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func(ctx context.Context, wg *sync.WaitGroup) {
		for {
			select {
			case <-ctx.Done():
				if err := ctx.Err(); err != context.Canceled || err != nil {
					log.Printf("failed to generate cert template, error: %v", err)
				}
				log.Println("finished generating cert from template")
				wg.Done()
				return
			default:
				if err, _ := s.GenerateCertTemplate(ctx, wg); err != nil {
					log.Fatalf("failed to generate cert template, error: %v", err)
				}
			}
			wg.Wait()
		}
	}(ctx, wg)
	defer wg.Done()
	wg.Add(1)
	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
		default:
		}
	}
}
