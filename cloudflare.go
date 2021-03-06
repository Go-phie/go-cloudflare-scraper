package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/robertkrimen/otto"
)

const userAgent = `Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36`

type Transport struct {
	upstream http.RoundTripper
	Cookies  http.CookieJar
}

func NewClient() (c *http.Client, err error) {

	scraperTransport, err := NewTransport(http.DefaultTransport)
	if err != nil {
		return
	}

	c = &http.Client{
		Transport: scraperTransport,
		Jar:       scraperTransport.Cookies,
	}

	return
}

func NewTransport(upstream http.RoundTripper) (*Transport, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &Transport{upstream, jar}, nil
}

func (t Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("User-Agent") == "" {
		r.Header.Set("User-Agent", userAgent)
	}

	if r.Header.Get("Referer") == "" {
		r.Header.Set("Referer", r.URL.String())
	}

	resp, err := t.upstream.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	// Check if Cloudflare anti-bot is on
	serverHeader := resp.Header.Get("Server")
	if resp.StatusCode == 503 && (serverHeader == "cloudflare-nginx" || serverHeader == "cloudflare") {
		log.Printf("Solving challenge for %s", resp.Request.URL.Hostname())
		resp, err := t.solveChallenge(resp)

		return resp, err
	}

	return resp, err
}

var jschlRegexp = regexp.MustCompile(`value="(\w+)" id="jschl-vc"`)
var passRegexp = regexp.MustCompile(`name="pass" value="(.+?)"`)

func (t Transport) solveChallenge(resp *http.Response) (*http.Response, error) {
	time.Sleep(time.Second * 4) // Cloudflare requires a delay before solving the challenge

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(b))

	var params = make(url.Values)

	if m := jschlRegexp.FindStringSubmatch(string(b)); len(m) > 0 {
		params.Set("jschl_vc", m[1])
	}

	if m := passRegexp.FindStringSubmatch(string(b)); len(m) > 0 {
		params.Set("pass", m[1])
	}

	chkURL, _ := url.Parse("/cdn-cgi/l/chk_jschl")
	u := resp.Request.URL.ResolveReference(chkURL)

	js, err := t.extractJS(string(b))
	if err != nil {
		return nil, err
	}

	answer, err := t.evaluateJS(js, string(b))
	if err != nil {
		return nil, err
	}

	params.Set("jschl_answer", strconv.Itoa(int(answer)+len(resp.Request.URL.Host)))

	req, err := http.NewRequest("GET", fmt.Sprintf("%s?%s", u.String(), params.Encode()), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", resp.Request.Header.Get("User-Agent"))
	req.Header.Set("Referer", resp.Request.URL.String())

	log.Printf("Requesting %s?%s", u.String(), params.Encode())
	client := http.Client{
		Transport: t.upstream,
		Jar:       t.Cookies,
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

var jsRegexp = regexp.MustCompile(
	`setTimeout\(function\(\){\s*(var s,t,o,p, b,r,e,a,k,i,n,g,f, .+?\r?\n[\s\S]+?a\.value\s*=.+?)\r?\n(?:[^{<>]*},\s*(\d{4,}))?`,
)

var jsReplace1Regexp = regexp.MustCompile(`a\.value = `)
var jsReplace2Regexp = regexp.MustCompile(`t(\.innerHTML)?\s*=\s*.*?;`)
var rReplace = regexp.MustCompile(`r\s*=\s*t.*?;`)
var documentlines = regexp.MustCompile(`[a-z] = document.getElementById\(.*?\)\;`)
var jsReplace3Regexp = regexp.MustCompile(`[\n\\']`)
var emptyRegexStr = []*regexp.Regexp{jsReplace1Regexp, jsReplace2Regexp, jsReplace3Regexp, documentlines, rReplace}

var jsReplace4Regexp = regexp.MustCompile(`<span`)
var jsReplace5Regexp = regexp.MustCompile(`/span>`)
var jsReplace6Regexp = regexp.MustCompile(`; 121`)
var jsReplace7Regexp = regexp.MustCompile(`=/>`)
var pRegexp = regexp.MustCompile(`var p = .*?;`)
var convertK = regexp.MustCompile(`k = (\w+);`)

// Document : fake JS dom for document
type Document struct{
	innerHTML string
}

func (t Transport) evaluateJS(js string, body string) (int64, error) {
	matchesK := convertK.FindStringSubmatch(js)
	htmlComp := fmt.Sprintf(`\<div id\=\"%s.*?\">(.*?)\<\/div\>`, matchesK[1])
	innerHTMLK := regexp.MustCompile(htmlComp)
	innerDetails := innerHTMLK.FindStringSubmatch(body)[1]
	js = convertK.ReplaceAllString(js, "k = '" + matchesK[1] + "';")
	js = pRegexp.ReplaceAllString(js, "var p = document.innerHTML;")

	vm := otto.New()
	doc := &Document{}
	doc.innerHTML = innerDetails
	vm.Set("document", doc)
	fmt.Println(js)
	result, err := vm.Run(js)
	if err != nil {
		return 0, err
	}
	return result.ToInteger()
}


func (t Transport) extractJS(body string) (string, error) {
	matches := jsRegexp.FindStringSubmatch(body)
	if len(matches) == 0 {
		return "", errors.New("No matching javascript found")
	}
	
	js := matches[1]
	// Strip characters that could be used to exit the string context
	// These characters are not currently used in Cloudflare's arithmetic snippet
	for _, empt := range(emptyRegexStr) {
		js = empt.ReplaceAllString(js, "")
	}
	js = jsReplace4Regexp.ReplaceAllString(js, "'<span")
	js = jsReplace5Regexp.ReplaceAllString(js, "/span>'")
	js = jsReplace6Regexp.ReplaceAllString(js, "'; 121';")
	js = jsReplace7Regexp.ReplaceAllString(js, "='/'>")

	fmt.Println(js)
	return js, nil
}
