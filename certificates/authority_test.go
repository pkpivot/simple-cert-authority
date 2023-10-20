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

		It("Should be turned into PEM stream", func() {
			var cert, key, _ = CreateTemplateRootCertificateAndKey("fred")
			var w = &SpyWriter{}
			Expect(WritePemCertFile(*cert, *cert, &key, w)).Should(BeNil())
			Expect(len(w.buffer) > 0).Should(BeTrue())
			Expect(strings.HasPrefix(w.ToString(), "-----BEGIN CERTIFICATE-----")).Should(BeTrue())

			w = &SpyWriter{}
			Expect(WritePemPrivateKey(&key, w)).Should(BeNil())
			Expect(len(w.buffer) > 0).Should(BeTrue())
			Expect(strings.HasPrefix(w.ToString(), "-----BEGIN PRIVATE KEY-----")).Should(BeTrue())

		})
	})
	Context("We have a signing certificate", func() {
		It("Should create a signed certificate", func() {

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
