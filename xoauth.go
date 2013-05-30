// Package xoauth calculates a valid signature for use with Gmail IMAP XOAUTH
// and other 2-legged OAUTH1 Google applications.
//
// See http://github.com/agamz/xoauth for more information.
package xoauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"math/rand"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func escapeAndJoin(elems []string) string {

	for key := range elems {
		elems[key] = url.QueryEscape(elems[key])
	}
	return strings.Join(elems, "&")
}

func sortAndFormat(params map[string]string, joinChar, quoteChar string) string {
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var s []string
	for _, k := range keys {
		s = append(s, k+"="+quoteChar+url.QueryEscape(params[k])+quoteChar)
	}
	return strings.Join(s, joinChar)
}

func generateSignatureBaseString(method, request_url_base string, params map[string]string) string {
	return escapeAndJoin([]string{method, request_url_base, sortAndFormat(params, "&", "")})
}

func generateHmacSha1Signature(text, key []byte) string {
	hash := hmac.New(sha1.New, key)
	hash.Write(text)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func generateOauthSignature(consumerSecret, base, token string) string {
	key := escapeAndJoin([]string{consumerSecret, token})
	return generateHmacSha1Signature([]byte(base), []byte(key))
}

func generateCommonOauthParams(consumerKey, nonce, timestamp string) map[string]string {
	result := map[string]string{
		"oauth_consumer_key":     consumerKey,
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_version":          "1.0",
		"oauth_nonce":            nonce,
		"oauth_timestamp":        timestamp,
	}

	if "" == timestamp {
		result["oauth_timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	}

	if "" == nonce {
		rand.Seed(time.Now().UnixNano())
		result["oauth_nonce"] = strconv.FormatInt(rand.Int63(), 10)
	}
	return result
}

// GenerateXOauthString produces a cleartext string in the format required for OAUTH1 access.
// consumerKey and consumerSecret are used for 2-legged oauth.
// oauthToken and oauthTokenSecret are set to "" for 2-legged oauth but can be provided if known (e.g. a previously stored token).
// user is the email address, including the domain, whose data you are trying to access
// proto should be set to "imap" for accessing Gmail IMAP
// xoauth_requestor_id should be set to the user's email address for IMAP xoauth requests
// nonce and timestamp should be "" and will calculated automatically.
//
// If you wish to encode the string ready to use with the IMAP "AUTHORIZE OAUTH <encoded_string>" command, then use the following:
//  xoauthstr := GenerateXOauthString(...)
//  encoded_string := base64.StdEncoding.EncodeToString([]byte(xoauthstr))
func GenerateXOauthString(consumerKey, consumerSecret, oauthToken, oauthTokenSecret, user, proto, xoauth_requestor_id, nonce, timestamp string) string {
	method := "GET"
	url_params := map[string]string{}

	if "" != xoauth_requestor_id {
		url_params["xoauth_requestor_id"] = xoauth_requestor_id
	}

	oauth_params := generateCommonOauthParams(consumerKey, nonce, timestamp)
	if "" != oauthToken {
		oauth_params["oauth_token"] = oauthToken
	}

	signed_params := oauth_params
	for k, v := range url_params {
		signed_params[k] = v
	}
	request_url := "https://mail.google.com/mail/b/" + user + "/" + proto + "/"
	base_string := generateSignatureBaseString(method, request_url, signed_params)
	oauth_params["oauth_signature"] = generateOauthSignature(consumerSecret, base_string, oauthTokenSecret)

	param_list := sortAndFormat(oauth_params, ",", "\"")

	return strings.Join([]string{method, request_url, param_list}, " ")
}
