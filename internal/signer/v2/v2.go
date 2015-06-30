package v2

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"sort"
	"strings"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"time"
	"net/url"
	"io"
	"log"
	"fmt"
)

const (
	authHeaderPrefix = "AWS"
	timeFormat       = "Mon, 2 Jan 2006 15:04:05 -0700"
	shortTimeFormat  = "20060102"
)

var ignoredHeaders = map[string]bool{
	"Authorization":  true,
	"Content-Type":   true,
	"Content-Length": true,
	"User-Agent":     true,
}

var s3ParamsToSign = map[string]bool{
	"acl":                          true,
	"delete":                       true,
	"location":                     true,
	"logging":                      true,
	"notification":                 true,
	"partNumber":                   true,
	"policy":                       true,
	"requestPayment":               true,
	"torrent":                      true,
	"uploadId":                     true,
	"uploads":                      true,
	"versionId":                    true,
	"versioning":                   true,
	"versions":                     true,
	"response-content-type":        true,
	"response-content-language":    true,
	"response-expires":             true,
	"response-cache-control":       true,
	"response-content-disposition": true,
	"response-content-encoding":    true,
}

type Signer struct {
	Request     *http.Request
	Time        time.Time
	ExpireTime  time.Duration
	ServiceName string
	Region      string
	CredValues  credentials.Value
	Credentials *credentials.Credentials
	Query       url.Values
	Body        io.ReadSeeker
	Debug       uint
	Logger      io.Writer

	isPresign          bool
	formattedTime      string
	formattedShortTime string

	signedHeaders    string
	canonicalHeaders string
	canonicalString  string
	credentialString string
	stringToSign     string
	signature        string
	authorization    string
}

func Sign(req *aws.Request) {
	// If the request does not need to be signed ignore the signing of the
	// request if the AnonymousCredentials object is used.
	if req.Service.Config.Credentials == credentials.AnonymousCredentials {
		return
	}

	region := req.Service.SigningRegion
	if region == "" {
		region = req.Service.Config.Region
	}

	name := req.Service.SigningName
	if name == "" {
		name = req.Service.ServiceName
	}

	s := Signer{
		Request:     req.HTTPRequest,
		Time:        req.Time,
		ExpireTime:  req.ExpireTime,
		Query:       req.HTTPRequest.URL.Query(),
		Body:        req.Body,
		ServiceName: name,
		Region:      region,
		Credentials: req.Service.Config.Credentials,
		Debug:       req.Service.Config.LogLevel,
		Logger:      req.Service.Config.Logger,
	}

	req.Error = s.Sign()
}

func (v2 *Signer) Sign() error {
	if v2.ExpireTime != 0 {
		v2.isPresign = true
	}

	if false {	//v2.isRequestSigned() {
		if !v2.Credentials.IsExpired() {
			// If the request is already signed, and the credentials have not
			// expired yet ignore the signing request.
			return nil
		}

		// The credentials have expired for this request. The current signing
		// is invalid, and needs to be request because the request will fail.
		if v2.isPresign {
			//			v2.removePresign()
			// Update the request's query string to ensure the values stays in
			// sync in the case retrieving the new credentials fails.
			v2.Request.URL.RawQuery = v2.Query.Encode()
		}
	}

	var err error
	v2.CredValues, err = v2.Credentials.Get()
	if err != nil {
		return err
	}

	if v2.isPresign {
		//		v2.Query.Set("X-Amz-Algorithm", authHeaderPrefix)
		if v2.CredValues.SessionToken != "" {
			v2.Query.Set("X-Amz-Security-Token", v2.CredValues.SessionToken)
		} else {
			v2.Query.Del("X-Amz-Security-Token")
		}
	} else if v2.CredValues.SessionToken != "" {
		v2.Request.Header.Set("X-Amz-Security-Token", v2.CredValues.SessionToken)
	}

	v2.build()

	if v2.Debug > 0 {
		v2.logSigningInfo()
	}

	return nil
}

func (v2 *Signer)build() error {

	v2.buildTime()             // no depends
	//	v2.buildCredentialString() // no depends
	//	if v2.isPresign {
	//		v2.buildQuery() // no depends
	//	}
	v2.buildCanonicalHeaders() // depends on cred string
	v2.buildCanonicalString()  // depends on canon headers / signed headers
	v2.buildStringToSign()     // depends on canon string
	v2.buildSignature()        // depends on string to sign

	if v2.isPresign {
		// TODO : Check if url contains AWSAccessKeyId and Expires
		v2.Request.URL.RawQuery += "&Signature=" + v2.signature
	} else {
		v2.Request.Header.Set("Authorization",
			authHeaderPrefix + " " + v2.CredValues.AccessKeyID + ":" + v2.signature)
	}

	return nil
}

func (v2 *Signer)buildSignature() {
	hmac := hmac.New(sha1.New, []byte(v2.CredValues.SecretAccessKey))
	hmac.Write([]byte(v2.stringToSign))
	v2.signature = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
}

func (v2 *Signer) buildStringToSign() {
	v2.stringToSign = strings.Join([]string{
		v2.Request.Method,
		v2.Request.Header.Get("Content-MD5"),
		v2.Request.Header.Get("Content-Type"),
		v2.Request.Header.Get("Date"),
		v2.canonicalHeaders,
		v2.canonicalString,
	}, "\n")
}

func (v2 *Signer) buildCanonicalString() {
	s := ""
	// URI
	if false {
		// TODO : support virtual hosting buncket
	} else {
		uri := v2.Request.URL.Opaque
		uri = strings.TrimPrefix(uri, "//")
		s = strings.TrimPrefix(uri, v2.Request.URL.Host)
	}
	if s == "" {
		s = "/"
	}

	// Sub resources
	q := strings.Split(v2.Request.URL.RawQuery, "&")
	sarray := []string{}
	for _, qv := range q {
		qp := strings.Split(qv, "=")
		if len(qp) < 2 {
			continue
		}
		log.Print(qp)
		k, v := qp[0], qp[1]
		if s3ParamsToSign[k] {
			if v == "" {
				sarray = append(sarray, k)
			} else {
				// "When signing you do not encode these values."
				sarray = append(sarray, k+"="+v)
			}
		}
	}
	if len(sarray) > 0 {
		sort.StringSlice(sarray).Sort()
		s += "?" + strings.Join(sarray, "&")
	}

	v2.canonicalString = s
}

func (v2 *Signer) buildCanonicalHeaders() {
	hs := map[string][]string{}
	for k, v := range v2.Request.Header {
		if ignoredHeaders[k] {
			continue
		}
		k = strings.ToLower(k)
		hs[k] = append(hs[k], v...)
	}
	sarray := []string{}
	for k, v := range hs {
		sarray = append(sarray, k+":" + strings.Join(v, ","))
	}
	if len(sarray) > 0 {
		sort.StringSlice(sarray).Sort()
		v2.canonicalHeaders = strings.Join(sarray, "\n")
	}
}

func (v2 *Signer) buildTime() {
	v2.formattedTime = v2.Time.UTC().Format(timeFormat)
	if v2.Request.Header.Get("Date") == "" {
		v2.Request.Header.Set("x-amz-date", v2.formattedTime)
	}
}

func (v2 *Signer) logSigningInfo() {
	out := v2.Logger
	fmt.Fprintf(out, "---[ CANONICAL STRING  ]-----------------------------\n")
	fmt.Fprintln(out, v2.canonicalString)
	fmt.Fprintf(out, "---[ STRING TO SIGN ]--------------------------------\n")
	fmt.Fprintln(out, v2.stringToSign)
	if v2.isPresign {
		fmt.Fprintf(out, "---[ SIGNED URL ]--------------------------------\n")
		fmt.Fprintln(out, v2.Request.URL)
	}
	fmt.Fprintf(out, "-----------------------------------------------------\n")
}
