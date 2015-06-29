package v2

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"bytes"
	"net/http"
	"sort"
	"strings"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
//	"github.com/aws/aws-sdk-go/internal/protocol/rest"
)

const (
	authHeaderPrefix = "AWS4-HMAC-SHA256"
	timeFormat       = "20060102T150405Z"
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

type signer struct {
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

	s := signer{
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

	req.Error = s.sign()
}

func (v2 *signer) sign() error {
	var md5, ctype, date, xamz string
	var xamzDate bool
	var sarray []string

	// add temporal security token
	if v2.CredValues.SessionToken != "" {
		v2.Request.Header.Set("x-amz-security-token", v2.CredValues.SessionToken)
	}

	if v2.credentialString ==  "" {
		// no auth secret; skip signing, e.g. for public read-only buckets.
		return
	}

	for k, v := range v2.Request.Header {
		k = strings.ToLower(k)
		switch k {
		case "content-md5":
			md5 = v[0]
		case "content-type":
			ctype = v[0]
		case "date":
			if !xamzDate {
				date = v[0]
			}
		default:
			if strings.HasPrefix(k, "x-amz-") {
				vall := strings.Join(v, ",")
				sarray = append(sarray, k+":"+vall)
				if k == "x-amz-date" {
					xamzDate = true
					date = ""
				}
			}
		}
	}
	if len(sarray) > 0 {
		sort.StringSlice(sarray).Sort()
		xamz = strings.Join(sarray, "\n") + "\n"
	}

	expires := false
	if err := v2.Request.ParseForm(); er != nil {
		return err
	}
	if v := v2.Request.Form.Get("Expires"); len(v) > 0 {
		// Query string request authentication alternative.
		expires = true
		date = v[0]
		v2.Request.Form.Add("AWSAccessKeyId", v2.CredValues.AccessKeyID)
	}

	sarray = sarray[0:0]
	for k, v := range v2.Request.Form {
		if s3ParamsToSign[k] {
			for _, vi := range v {
				if vi == "" {
					sarray = append(sarray, k)
				} else {
					// "When signing you do not encode these values."
					sarray = append(sarray, k+"="+vi)
				}
			}
		}
	}
	if len(sarray) > 0 {
		sort.StringSlice(sarray).Sort()
		v2.canonicalString = v2.canonicalString + "?" + strings.Join(sarray, "&")
	}

	payload := v2.Request.Method + "\n" + md5 + "\n" + ctype + "\n" + date + "\n" + xamz + v2.canonicalString
	hash := hmac.New(sha1.New, []byte(v2.CredValues.SecretAccessKey))
	hash.Write([]byte(payload))

	signature := make([]byte, 0)
	b64 := base64.NewEncoder(base64.URLEncoding,bytes.NewBuffer(signature))
	b64.Write(hash.Sum(nil))

	if expires {
		v2.Request.Form.Set("Signature", signature)
	} else {
		v2.Request.Header.Set("Authorization", "AWS " + v2.CredValues.AccessKeyID + ":" + string(signature))
	}

//	if debug {
//		log.Printf("Signature payload: %q", payload)
//		log.Printf("Signature: %q", signature)
//	}
	return nil
}


