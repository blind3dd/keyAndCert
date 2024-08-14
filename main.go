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

	"github.com/google/uuid"
)

type seed struct {
	seeder seeder
	Key    uint64
	keyPK  uint64
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
) (string, error) {

	ctxtd := context.WithValue(ctx, 123213, pkey)
	privKey, ok := ctxtd.Value(123213).(*rsa.PrivateKey)
	if !ok {
		log.Fatalf("failed to type assert the variable type: %v", privKey)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
	if err := writeFile("key.pem", pemBytes); err != nil {
		log.Fatalf("failed to write key to a file, error: %v", err)
	}

	return string(pemBytes), nil
}

func writeFile(fname string, pemb []byte) error {
	fileMutex.Lock()
	defer fileMutex.Unlock()
	f, _ := os.Create(fname)
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)
	if _, err := f.Write(pemb); err != nil {
		panic(err)
	}

	return nil
}

func generateCert(
	ctx context.Context,
	certBytes []byte,
) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err := writeFile("cert.pem", pemBytes); err != nil {
		log.Fatalf("failed to write cert to a file, error: %v", err)
	}
	return string(pemBytes), nil
}

func generateKeyAndCert(ctx context.Context, x509t *x509.Certificate) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	certBytes, _ := x509.CreateCertificate(rand.Reader, x509t, x509t, &privKey.PublicKey, privKey)
	privKeyChan := make(chan string, 1)
	errChan := make(chan error, 1)
	close(privKeyChan) // %CHANNEL%

	go func() {
		err := func() error {
			log.Println("generating a private key")
			pkey, _ := generatePrivateKey(ctx, privKey)
			defer func() {
				if r := recover(); r != nil {

					// if we do not recover this here
					// closing the channel %CHANNEL% then we won't see one priv key output (perhaps we shouldn't!)
					err := fmt.Errorf("recovered: %s %s", r.(error).Error(), pkey)
					err = fmt.Errorf("key pem: %s", pkey)
					errChan <- err // Here We say LOG IT :)
				}
			}()

			select {
			case <-ctx.Done():
				log.Printf("key pem: %s", pkey)
				return <-errChan
			case <-time.After(1 * time.Millisecond):
				log.Printf("key pem: %s", pkey)
				return <-errChan
			case privKeyChan <- pkey:
				log.Printf("key pem: %s", pkey)
				return <-errChan
			}
		}() // this Does not matter because of close invoked in line 167
		if err != nil {
			panic(err)
		}
	}()
	log.Println(<-errChan)

	certChan := make(chan string, 1)
	errorChan := make(chan error, 1)
	go func() {
		log.Println("generating a cert file")
		err := func() error {
			cert, err := generateCert(ctx, certBytes)
			if err != nil {

				errorChan <- err
				return <-errorChan
			}
			certChan <- cert

			return nil
		}()
		if err != nil {
			log.Printf("error: %v", err.Error())
		}
	}()

	select {
	case cc := <-certChan:
		log.Printf("cert pem: %s", cc)
	case <-ctx.Done():
		log.Printf("context error: %v", ctx.Err())
	case err := <-errorChan:
		log.Printf("error: %v", err.Error())
	}
}

func main() {
	log.Println("program is starting")
	s := &seed{}
	time.Sleep(500 * time.Millisecond)
	sn := new(big.Int).SetUint64(s.GetSerialNumber())

	uid7 := s.GetUUIDv7()
	var key, _ = s.transformToInt(uid7)
	ctx := context.Background()
	ctx = context.WithValue(ctx, key, sn)
	log.Println("running goroutines to generate key and cert")

	errChan := make(chan error, 1)
	templChan := make(chan x509.Certificate, 1)

	go func(ctx context.Context) {
		x509t, err := s.GenerateCertTemplate(ctx)
		if err != nil {
			errChan <- err
		}
		templChan <- *x509t
	}(ctx)
	select {
	case tc := <-templChan:
		log.Println("generating template for a cert")
		generateKeyAndCert(ctx, &tc)
	case err := <-errChan:
		log.Printf("error: %v", err.Error())
	}
}

var (
	fileMutex sync.Mutex
)
