package main

import (
	"crypto/x509"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"strings"
)

var _ = Describe("Root certificate tests", func() {
	Context("no root cert", func() {
		It("Should return certificate and valid key", func() {

			//Expect(CreateRootCertificateAndKey("fred")).Should(BeNil())

			var cert, key, err = CreateTemplateRootCertificateAndKey("fred")
			Expect(err).Should(BeNil())
			Expect(cert).ShouldNot(BeNil())
			Expect(key.Validate()).Should(BeNil())
		})

		It("Should be signing cert", func() {
			var cert, _, _ = CreateTemplateRootCertificateAndKey("fred")
			Expect(cert.KeyUsage & x509.KeyUsageCertSign).Should(Equal(x509.KeyUsageCertSign))

		})
		It("Should have specified issuer", func() {
			var cert, _, _ = CreateTemplateRootCertificateAndKey("fred")
			Expect(cert.Subject.Organization[0]).Should(Equal("fred"))

		})

		It("Should always have a different serial number", func() {
			var cert1, _, _ = CreateTemplateRootCertificateAndKey("fred")
			var cert2, _, _ = CreateTemplateRootCertificateAndKey("fred")

			Expect(*cert1.SerialNumber).ShouldNot(Equal(*cert2.SerialNumber))
		})

		It("Should be turned into PEM stream", func() {
			var cert, key, _ = CreateTemplateRootCertificateAndKey("fred")
			var w = &SpyWriter{}
			Expect(WritePemCertFile(*cert, *cert, &key, w)).Should(BeNil())
			Expect(len(w.buffer) > 0).Should(BeTrue())
			Expect(strings.HasPrefix(w.ToString(), "-----BEGIN CERTIFICATE-----")).Should(BeTrue())
			Expect(strings.HasSuffix(strings.TrimSpace(w.ToString()), "-----END CERTIFICATE-----")).Should(BeTrue())

			w = &SpyWriter{}

			Expect(WritePemPrivateKey(&key, w)).Should(BeNil())
			Expect(len(w.buffer) > 0).Should(BeTrue())
			Expect(strings.HasPrefix(w.ToString(), "-----BEGIN PRIVATE KEY-----")).Should(BeTrue())
			Expect(strings.HasSuffix(strings.TrimSpace(w.ToString()), "-----END PRIVATE KEY-----")).Should(BeTrue())

		})
	})
	Context("We have a signing certificate", func() {
		signingCert, signingKey, _ := CreateTemplateRootCertificateAndKey("authority.example.com")
		It("Should create a signed certificate", func() {
			var clientCert, _, err = CreateTemplateCertificateAndKey("client.example.com")
			Expect(err).Should(BeNil())
			var w = &SpyWriter{}
			Expect(WritePemCertFile(*clientCert, *signingCert, &signingKey, w)).Should(BeNil())
			Expect(len(w.buffer) > 0).Should(BeTrue())
			Expect(strings.HasPrefix(w.ToString(), "-----BEGIN CERTIFICATE-----")).Should(BeTrue())
			Expect(len(clientCert.DNSNames) > 0).Should(BeTrue())
			Expect(clientCert.DNSNames[0]).Should(Equal("client.example.com"))

		})

		It("Should always use a different serial number", func() {
			var cert1, _, _ = CreateTemplateCertificateAndKey("client.example.com")
			var cert2, _, _ = CreateTemplateCertificateAndKey("client.example.com")
			Expect(*cert1.SerialNumber).ShouldNot(Equal(*cert2.SerialNumber))
		})
	})

	Context("We are creating key and cert filenames", func() {
		It("Should generate certset.pem and certset-key.pem names", func() {
			certName, keyName := CertSetNames("certificate")
			Expect(certName).Should(Equal("certificate.pem"))
			Expect(keyName).Should(Equal("certificate-key.pem"))
		})
		It("Should ignore extensions in certificate set name", func() {
			certName, keyName := CertSetNames("certificate.xxx")
			Expect(certName).Should(Equal("certificate.pem"))
			Expect(keyName).Should(Equal("certificate-key.pem"))
		})
	})

	Context("Certificate and key PEM files exist", func() {
		It("Should decode a certificate in PEM format", func() {
			cert, err := ReadPemCert([]byte(PemCertificate))
			Expect(err).Should(BeNil())
			Expect(cert).ShouldNot(BeNil())
			Expect(cert.KeyUsage).Should(Equal(x509.KeyUsageCertSign))
		})

		It("Should decode a private key in PEM format", func() {
			key, err := ReadPemKey([]byte(PemKey))
			Expect(err).Should(BeNil())
			Expect(key).ShouldNot(BeNil())
			//Expect(cert.KeyUsage).Should(Equal(x509.KeyUsageCertSign))
		})

	})
})

type SpyWriter struct {
	buffer []byte
}

func (sw *SpyWriter) Write(p []byte) (n int, err error) {
	sw.buffer = append(sw.buffer, p...)
	return 0, nil
}

func (sw *SpyWriter) ToString() string {
	return string(sw.buffer)
}

// Test data
const PemCertificate = `-----BEGIN CERTIFICATE-----
MIIC2zCCAcOgAwIBAgIBATANBgkqhkiG9w0BAQ0FADAPMQ0wCwYDVQQKEwRmcmVk
MB4XDTIzMTAzMTE1Mzg0OFoXDTI0MTAzMDE1Mzg0OFowDzENMAsGA1UEChMEZnJl
ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOjD2a2rMzTsOQS8qK0c
zFwvGA472Mhs2fa2kloTpGORJB5l8XsUQwEhqRMM7nrqE02J5VIFTtUCmNrbjosq
X+7vy6d8dTluJddVeMLzom+cDN7vVot2rN3X4bk/ZE22EB0q8m76qj3gCcy9TnS7
EHGLN6jrh8qV7oyzkM+wDiEivyznFxtIONc8pYtveKHffehydaCu+RdgYVFemJo0
2lFOzLsC4zKm0cfPtDMprSrvMPcJ7u8xUsNZVkdYoSllVhvgKwwR64NX2ztGSoMN
Vr/beATWeAtWMGlBDhQsBjhjBFri/F9E7pdbVZkpj1zI4e8OO6x+Z0rxSrKp8Ak8
yU8CAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgIEMA8GA1UdEwEB/wQFMAMBAf8wHQYD
VR0OBBYEFNdRxNa2QUNm2BSYGYd0KrEOP/agMA0GCSqGSIb3DQEBDQUAA4IBAQAX
ZqfSVJNJx2pu2EoJtmBA7SU7yinyKt3FexC9w0ggiDEinlv3AWb6PsZHtfZC3YM3
0RAAkFZrssvqmxN1J5HMV2ppEMxQd4yOb0LIf53b+B1shnO0chknnIYJW29Pc89X
ioydc7NUHJkjrf+dfM7CKmkZJnQ/zLgE4N+0SnF6CsaP5JfIrB7PDLfI3liQRyLs
Uzfv39GnPYMJyU9V5jVsRCHckd3ubjG+rJvY4OwRAGNCbhH0xP8uexS2s+BACI8f
FpUVHdVEEBcJaBBwntICHTr2vx7WXYSubvhHojSabCpp027D43k4/14VKbucqMor
AZJ57JExnlKoLqQFRUsf
-----END CERTIFICATE-----`

const PemKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDgWlBY2vhL6OQN
DcFQgtMQo8ej0GSSImmHTjO0wpspx6VHeyTcWEiaPfy/9cAj1gcsAcybwbSexM/R
ofBxlVQS7NWo7JYcOXmv/kYEkaN3qROwev2lBerW+spF65Tk2LbHti515JmkXqap
V1dnJI3GVzUyRtSf9c05vvrwq1mdkNUGcrks/TqeVNLN5M7GwDyi6oUZpg/l7Nnt
eDCO0yd0eiU9i4gEDh4iI6pLOqmrWY057aH9s/1wwte6xxmlvJBg0tSUgnEfjvoz
rASQXrmE+wfzuTQc6PTWDSIOc/NWQ0mibCnP+dDGt+W+jcTdJuqAAtKSLbdZ9x9B
Cn8UHJu/AgMBAAECggEBANKIbfW0JmU1uyv0yIABBIgM6X90Q6xO1rC+Vg8+v9TJ
IPSfPsv3nMoBeXm56AC5DCnj1lojwJdtIYgba0NrWmYYEbhfq834sZTSDGqlML1N
0Mg/4l5F20a6Oa67kBHgvEVVVOwVBYkVuVgYOlD0IIcLt0Pi7Azf4SJbcaj/Yy1T
xmlH/slEkU/FZmXUz441qUQXB8zKxvcoN8xllU4ncw5Tr1fk1u1qTSuMvvqQI+F/
yDxRmgEaKO70j0wOL3m/s0s4v8gd9h1BWeMItiloxvxws74CBRWI66/rmI6nU0aM
X9+bMXJbEZApxBpf2ZgPt1nTCIXI+hHZe5rw++nk3aECgYEA6gmp6oG/djEpGWcE
PNWnM4ctxBLOAQ9DgIBQ8xhOosJmeqva1wz8vN9HhHRvgSNDBw+12YLnPKZogFHe
Ps59mU2FJ4VGkotYsGt7IqJfQR23IHYjXBIJ0PpG8e2yOuYnZZtexJTjTwB7nglw
qphjZtOw1N12wtDvEjgKf5XQ7J0CgYEA9Wf8gawTlMFCviI/XymBGlFM6ed7BDli
myjdPRTCjX8MbtzMpvcppTyw+rvoJzWacCLRRgd2NmM7EAbmLRPS1UNObe8obdvk
8BnvAjB4hGL4gq1/c/Er9cABGFvEKPhgmM0UWdXidUXp4EqNIG38FAaWv1jDz1fZ
FzkzUcBC5QsCgYA86XD44PYU6+yXePFoZ+8RgTBPJNnK+s8Fxd/LtVraD6CectYN
PIsXGUHC3o8a3DOYxeT9jI1kgqcWJriiPhoAaWWriIt6npvhpsewlvQVvYcpArZn
Qyac5lbKpqPJopdEYbDDl0CmEikaU7ioHetZGuWeMVm0kK54Xm+VD0gGHQKBgFS+
JuUEbfKVVh3gJ7AN3gYfgwbWp5VK17EqyFM6YwCHmdyCpK0XdqsXrSm4T6+ShBUr
AMdE9l5Ln+6l40A3sztvtZqi1nwxTfpXikBgSo20u4osrXF1G7AOMJKfxbo8IudB
EkD/aecDUILiW5+SO1US/WVwGpX0CQRK/VzCnpcHAoGBAK+xa2u5U40sBUsN/i6h
pk3/R3fFS5Qc34VJ6RMCa2pooFHon2tNY5xfWqLqL+C+acTvoME0Az0KtBmaPP6k
Zb9bVlXGMUJLi+vAc+pXrtjFMdI5WXpOOEHs2jxy2FeprxfR+dG+5cM3dKqOietn
5kc5TGUcfNytLH9hTHy2Ydf+
-----END PRIVATE KEY-----
`
