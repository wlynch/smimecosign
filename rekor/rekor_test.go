package rekor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

// uuid generates the UUID for the given LogEntry.
// This is effectively a reimplementation of
// pkg/cosign/tlog.go -> verifyUUID / ComputeLeafHash, but separated
// to avoid a circular dependency.
// TODO?: Perhaps we should refactor the tlog libraries into a separate
// package?
func uuid(e models.LogEntryAnon) string {
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(entryBytes))
}

type mockEntriesService struct {
	entries.ClientService
	data models.LogEntry
}

func (s *mockEntriesService) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams, opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	return &entries.GetLogEntryByUUIDOK{
		Payload: s.data,
	}, nil
}

type mockIndexService struct {
	index.ClientService
	data []string
}

func (s *mockIndexService) SearchIndex(params *index.SearchIndexParams, opts ...index.ClientOption) (*index.SearchIndexOK, error) {
	return &index.SearchIndexOK{
		Payload: s.data,
	}, nil
}

func TestGet(t *testing.T) {

	key, err := cosign.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("error generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
	}
	b, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("error generating cert: %v", err)
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatalf("error parsing certificate: %v", err)
	}
	/*
		pkBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("error marshalling public key: %v", err)
		}
	*/

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	})
	entry := rekorEntry([]byte("foo"), []byte("bar"), pemBytes)
	id := uuid(entry)
	client := &Client{
		Rekor: &client.Rekor{
			Index: &mockIndexService{
				data: []string{id},
			},
			Entries: &mockEntriesService{
				data: models.LogEntry{
					id: entry,
				},
			},
		},
	}

	ctx := context.Background()
	if _, err := client.Get(ctx, "", cert); err != nil {
		t.Fatal(err)
	}
}

func rekorEntry(payload, signature, pubKey []byte) models.LogEntryAnon {
	// TODO: Signatures created on a digest using a hash algorithm other than SHA256 will fail
	// upload right now. Plumb information on the hash algorithm used when signing from the
	// SignerVerifier to use for the HashedRekordObj.Data.Hash.Algorithm.
	h := sha256.Sum256(payload)
	re := hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
					Value:     swag.String(hex.EncodeToString(h[:])),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(pubKey),
				},
			},
		},
	}
	hr := models.Hashedrekord{
		APIVersion: swag.String(re.APIVersion()),
		Spec:       re.HashedRekordObj,
	}
	b, _ := hr.MarshalJSON()
	return models.LogEntryAnon{
		Body: base64.StdEncoding.EncodeToString(b),
	}
}
