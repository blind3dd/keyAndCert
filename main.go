package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
)

type seed struct {
	seeder seeder
	Key    uint64
}

type seeder interface {
	GenerateCertTemplate(ctx context.Context) *x509.Certificate
	GetSerialNumber() uint64
	GetUUIDv7() string
	transformToInt(uuid uuid.UUID) (uint64, error)
}

func (s *seed) GetUUIDv7() uuid.UUID {
	u7, err := uuid.NewV7()
	if err != nil {
		log.Printf("failed to generate the uuid, error:%v", err)
	}

	return u7
}

func (s *seed) transformToInt(uuid uuid.UUID) (uint64, error) {
	uuid = s.GetUUIDv7()
	var b []uint8
	b, err := uuid.MarshalBinary()
	if err != nil {
		log.Printf("failed to marshal the uuid to binary, error:%v\n", err)
	}
	uuidInt := int64(binary.LittleEndian.Uint64(b[:]))
	mrand.New(mrand.NewSource(uuidInt)).Seed(uuidInt)
	ui := big.NewInt(uuidInt).Exp(big.NewInt(2), big.NewInt(130), nil)
	u, err := rand.Int(rand.Reader, ui)

	s.Key = u.Uint64()

	return s.Key, nil
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
		log.Fatalf("failed to proceed, error: %v", err)
	}

	return n.Uint64()
}

func (s *seed) GenerateCertTemplate(ctx context.Context) (
	*x509.Certificate,
	error,
) {
	sn, ok := ctx.Value(s.Key).(*big.Int)
	if !ok {
		log.Fatalf("failed to type assert the variable type: %v", sn)
	}
	x509t := x509.Certificate{
		SerialNumber: sn,
		Subject: pkix.Name{
			CommonName:   "com.apple.idms.appleid.test",
			Organization: []string{"Pawel Bek"},
			Country:      []string{"US,EU"},
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
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		EmailAddresses:        []string{"test@gmail.com"},
		DNSNames:              []string{"localhost"},
	}

	return &x509t, nil
}

func generatePrivateKey(
	ctx context.Context,
	pkey *rsa.PrivateKey,
) {
	ctxd, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	select {

	case <-ctxd.Done():
		if err := ctx.Err(); errors.Is(err, context.Canceled) {
			log.Printf("failed to generate private key, error: %v", err)
		}

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
		//default:
	}

}

func generateCert(
	ctx context.Context,
	certBytes []byte,
) {
	ctxe, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	select {
	case <-ctxe.Done():
		if err := ctx.Err(); errors.Is(err, context.Canceled) {
			log.Printf("failed to generate cert, error: %v", err)
		}
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
		//default:
	}
}

func (s *seed) contextRun(ctx context.Context) {
	x509t, _ := s.GenerateCertTemplate(ctx)
	ticker := time.NewTicker(duration)
	privKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	certBytes, _ := x509.CreateCertificate(rand.Reader, x509t, x509t, &privKey.PublicKey, privKey)

	ctxa, cancel := context.WithTimeout(ctx, duration)
	ctxb, _ := context.WithTimeout(ctxa, duration)
	defer cancel()
	for {
		select {
		case <-ticker.C:
			go generatePrivateKey(ctx, privKey)
			<-ctxa.Done()
			break
		case <-ctxb.Done():
			go generateCert(ctx, certBytes)
			<-ctxa.Done()
			break
			//ticker.Stop()
		default:
		}
	}
}

func main() {
	ctx := context.Background()
	log.Println("program is starting")
	s := &seed{}
	time.Sleep(500 * time.Millisecond)
	sn := new(big.Int).SetUint64(s.GetSerialNumber())

	uid7 := s.GetUUIDv7()
	var key, _ = s.transformToInt(uid7)

	ctx = context.WithValue(ctx, key, sn)
	log.Println("running goroutines to generate key and cert")

	err := func(ctx context.Context) error {
		s.contextRun(ctx)
		return nil
	}(ctx)
	if err != nil {
		panic(err)
	}

}

var (
	duration = 500 * time.Millisecond
)
