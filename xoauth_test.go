package xoauth

import (
	"github.com/stretchrcom/testify/assert"
	"strconv"
	"testing"
	"time"
)

func TestEscapeAndJoin(t *testing.T) {
	assert.Equal(t, "foo&bar", escapeAndJoin([]string{"foo", "bar"}), "joining two strings")
	assert.Equal(t, "foo&bar&3", escapeAndJoin([]string{"foo", "bar", "3"}), "joining three strings")
	assert.Equal(t, "foo%3F&bar", escapeAndJoin([]string{"foo?", "bar"}), "url encode the strings")
}

func TestSortAndFormat(t *testing.T) {
	johnsmith := map[string]string{"firstname": "john", "lastname": "smith"}
	assert.Equal(t, "firstname=john&lastname=smith",
		sortAndFormat(johnsmith, "&", ""), "convert map to URL string")
	assert.Equal(t, "firstname=\"john\",lastname=\"smith\"",
		sortAndFormat(johnsmith, ",", "\""), "convert map to URL string")
}

func TestGenerateSignatureBaseString(t *testing.T) {
	johnsmith := map[string]string{"firstname": "john", "lastname": "smith"}
	assert.Equal(t, "GET&http%3A%2F%2Fexample.com&firstname%3Djohn%26lastname%3Dsmith",
		generateSignatureBaseString("GET", "http://example.com", johnsmith), "combine strings")
}

func TestGenerateHmacSha1Signature(t *testing.T) {
	sometext := []byte("sometext")
	somekey := []byte("somekey")
	assert.Equal(t, "jBXFV2mUBNP0/iVeVrb1x2TfSSc=", generateHmacSha1Signature(sometext, somekey), "sha1 baby!")
	assert.NotEqual(t, generateHmacSha1Signature(sometext, sometext),
		generateHmacSha1Signature(sometext, somekey), "processing arg1 twice")
	assert.NotEqual(t, generateHmacSha1Signature(somekey, somekey),
		generateHmacSha1Signature(sometext, somekey), "processing arg2 twice")
}

func TestGenerateOauthSignature(t *testing.T) {
	consumerSecret := "consumersecret"
	baseString := "basestring"
	tokenSecret := "tokensecret"
	assert.Equal(t, generateOauthSignature(consumerSecret, baseString, tokenSecret), "87jCloDPrB5/bFk40g3TKpZQc28=", "hash magic!")

}

func TestGenerateCommonOauthParams(t *testing.T) {
	consumerKey := "consumerkey"
	nonce := "1234123412341234"
	timestamp := "1369804368"
	result := map[string]string{"oauth_consumer_key": "consumerkey",
		"oauth_nonce":            nonce,
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_version":          "1.0",
		"oauth_timestamp":        timestamp,
	}

	assert.Equal(t, generateCommonOauthParams(consumerKey, nonce, timestamp), result, "common params")
	result["oauth_timestamp"] = "0"
	assert.NotEqual(t, generateCommonOauthParams(consumerKey, nonce, timestamp), result, "should fail")
	assert.Equal(t, generateCommonOauthParams(consumerKey, nonce, "0"), result, "data changed")

	result["oauth_timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	assert.Equal(t, generateCommonOauthParams(consumerKey, nonce, ""), result, "using current time")

	result2 := generateCommonOauthParams(consumerKey, "", "")
	assert.True(t, len(result2["oauth_nonce"]) >= 18, "nonce is >= 18 chars (fails occaisionally because of a small random number)")
}

func TestGenerateXOauthString(t *testing.T) {
	assert.Equal(t, GenerateXOauthString("consumerkey", "consumersecret", "oauth_token", "oauth_token_secret", "user", "proto", "requestorid", "nonce", "timestamp"),
		"GET https://mail.google.com/mail/b/user/proto/ oauth_consumer_key=\"consumerkey\",oauth_nonce=\"nonce\",oauth_signature=\"ZyPZU7GvYbOcA8db%2BQpZuMELnts%3D\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"timestamp\",oauth_token=\"oauth_token\",oauth_version=\"1.0\",xoauth_requestor_id=\"requestorid\"", "should be a url ready to go")
}
