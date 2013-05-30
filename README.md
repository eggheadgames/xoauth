# XOAuth

XOAuth provides a [Go](http://golang.org/) implementation of 
[two-legged oauth](https://developers.google.com/gdata/docs/auth/oauth#2LeggedOAuth) 
for logging into Gmail via IMAP using its XOAUTH protocol support.

Although OAuth 1.x has been [officially deprecated](https://developers.google.com/gmail/oauth_protocol) by Google, 
it remains the only way to build apps that allow for domain-wide delegation of authority. 

As [Google states](https://developers.google.com/accounts/docs/OAuth#GoogleAppsOAuth):

> Using 2-legged OAuth allows for domain-wide delegation of authority. 
> A domain administrator can authorize access requests for all users. 
> An application that has the OAuth consumer key and secret (roughly 
> equivalent to a role account username and password) is allowed to act 
> as any user in the domain when accessing Google Data APIs.

This implementation is based on a [Javascript implementation](https://github.com/yehezkielbs/gmail-xoauth) 
which is in turn derived from Google's 
[Python implementation](https://code.google.com/p/google-mail-xoauth-tools/source/browse/trunk/python/xoauth.py).

It can be used for regular OAuth client access if you already have tokens, but it has only been tested with the 
domain-wide consumer key and secret.

## Installation

Use the [go tool](http://weekly.golang.org/cmd/go/) to install XOAuth:

    go get github.com/agamz/xoauth


## Usage

To generate a valid string for use with the [Gmail XOAUTH login](https://developers.google.com/gmail/oauth_protocol#smtp_protocol_exchange), you will need:

 1. the email address you're going to access. This must be in a (Google Apps) domain that you have access to, or login will fail.
 2. the consumer key provided to you by Google
 3. the consumer secret provided to you by Google

Generate the string  as follows:

````Go
    include "github.com/agamz/xoauth"

    ...
    User := "some.person@example.com"
    ConsumerKey = "magic key"
    ConsumerSecret = "magic key secret"
    xoauthstring := xoauth.GenerateXOauthString(ConsumerKey, ConsumerSecret, "", "", User, "imap", User, "", "")
````

You can then pass this to your favourite Gmail IMAP library as needed.  For example, you can use the excellent [go-imap](https://code.google.com/p/go-imap/) library.
For that library, you'll need to provide an XOAUTH SASL implementation:

````Go
    type xoAuth []byte

    func XoAuth(identity string) imap.SASL {
            return xoAuth(identity)
    }

    func (a xoAuth) Start(s *imap.ServerInfo) (mech string, ir []byte, err error) {
            return "XOAUTH", a, nil
    }

    func (a xoAuth) Next(challenge []byte) (response []byte, err error) {
            return nil, errors.New("unexpected server challenge")
    }
````

Now you can call its `Auth` function to login:

````Go
    include "code.google.com/p/go-imap/go1/imap"

    func callimap() {
        var c *imap.Client

        ....
        xoauthstring := xoauth.GenerateXOauthString(ConsumerKey, ConsumerSecret, "", "", User, "imap", User, "", "")
        c.Auth(XoAuth(xoauthstring)))

        ....
    }
````

## Contributions

Contributions are welcome!  More examples or source code changes are both solicited. 

Please be sure that `go test` works before submitting pull requests.


##License

XOAuth is available under the [BSD License](http://opensource.org/licenses/BSD-3-Clause).


