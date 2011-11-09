# Installation

    goinstall github.com/reinaldons/goauth

# Usage

    import (
        "github.com/reinaldons/goauth"
        "os"
    )

    func someFuncThatDoesStuffWithOAuth() (err os.Error) {
        o := new (oauth.OAuth)
        o.ConsumerKey = "key"
        o.ConsumerSecret = "secret"
        o.Callback = "callback"

        o.RequestTokenURL = "https://api.twitter.com/oauth/request_token"
        o.OwnerAuthURL = "https://api.twitter.com/oauth/authorize"
        o.AccessTokenURL = "https://api.twitter.com/oauth/access_token"

        err = o.GetRequestToken()
        if err != nil { return }

        url, err := o.AuthorizationURL()
        if err != nil { return }

        // somehow send user to url...

        var verifier string
        // somehow get verifier (or "PIN")...

        err = o.GetAccessToken(verifier)
        if err != nil { return }

        err = o.Save(os.Getenv("HOME") + "/.simple_example.oauth")

        response, err := o.Post(
            "https://api.twitter.com/1/statuses/update.json",
            map[string]string{"status": "Just did a little OAuth dance!"})
        if err != nil { return }

        // do stuff with response...

        return nil
    }

# With access token and key saved

    o := new(oauth.OAuth)
    o.ConsumerKey = "app key"
    o.ConsumerSecret = "app secret"
    o.SignatureMethod = "HMAC-SHA1"

    o.AccessToken = "user access token"
    o.AccessSecret = "user access secret"

    get := make(map[string]string)
    header := make(map[string]string)
    response, err := o.Post("http://api.dropbox.com/0/account/info", "", get, header)
    if err != nil {
            fmt.Println("AccountInfo fail: ", err)
            return
    }

    fmt.Println("Response Body: ", bodyString(response.Body))

# Upload file

    func UploadFile(path string, filename string, content string) {
        boundary := fmt.Sprintf("mandic.gomda.%d", time.Nanoseconds())
        
        body := `--[--boundary--]
        Content-Disposition: form-data; name="file"; filename="[--filename--]"
        Content-type: text/plain
        
        [--content--]
        --[--boundary--]--
        
        `
        
        body = strings.Replace(body, "[--boundary--]", boundary, 2)
        body = strings.Replace(body, "[--filename--]", filename, 1)
        body = strings.Replace(body, "[--content--]", content, 1)
        
        get := make(map[string]string)
        get["file"] = filename
        header := make(map[string]string)
        header["User-Agent"] = "Mandic Dropbox"
        header["Content-Length"] = fmt.Sprintf("%d", len(body))
        header["Content-Type"] = fmt.Sprintf("multipart/form-data; boundary=%s", boundary)
        
        o := new(oauth.OAuth)
        o.ConsumerKey = "app key"
        o.ConsumerSecret = "app secret"
        o.SignatureMethod = "HMAC-SHA1"
        
        o.AccessToken = "user access token"
        o.AccessSecret = "user access secret"
        
        response, err := o.Post(fmt.Sprintf("http://api-content.dropbox.com/0/files/dropbox/%s", path), body, get, header)
        if err != nil {
                fmt.Println("UploadFile fail: ", err)
                return
        }
        
        fmt.Println("Response Body: ", bodyString(response.Body))
    }

# Status

This is still a bit of a work in progress.  The interface is subject to
change (and become prettier), but I think it's mostly done.

It is probably obvious that it's rough around the edges in spots.
Please let me know if anything's broken.
