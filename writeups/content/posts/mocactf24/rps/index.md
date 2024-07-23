+++
title = 'RPS'
date = 2023-01-15T09:00:00-07:00
draft = false
tags = ['mocactf24', 'challenge', 'symmetric', 'web', 'crypto']
+++
 
In this challenge we're given a rock-paper-scissors playing server with a
custom cookie system and our objective is to win 100 consecutive games.
The state is stored completely inside of a session cookie encrypted with 
a custom symmetric cipher.
```python3
import json
import os
from random import SystemRandom
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from zlib import crc32

from Crypto.Cipher import AES
from flask import Flask, make_response, render_template, request

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "PWNX{placeholder}")


class ChecksummedCipher:
    """add checksum to be safe from tampering"""

    CRC0 = crc32(b"\0\0\0\0")

    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(8)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        crc = crc32(plaintext)
        return nonce + cipher.encrypt(plaintext + crc.to_bytes(4, "little"))

    def decrypt(self, ciphertext: bytes) -> bytes:
        nonce = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        if not crc32(plaintext) == self.CRC0:
            raise ValueError("Invalid CRC")
        return plaintext[:-4]


class DoublyChecksummedCipher(ChecksummedCipher):
    """you can never be too safe"""

    def __init__(self, key: bytes):
        key = sha256(key).digest()
        super().__init__(key[16:])
        self.cipher = ChecksummedCipher(key[:16])

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.cipher.encrypt(super().encrypt(plaintext))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return super().decrypt(self.cipher.decrypt(ciphertext))


cc = DoublyChecksummedCipher(bytes.fromhex(os.environ.get("KEY")))


@dataclass
class GameState:
    won: int = 0
    tied: int = 0
    lost: int = 0
    played: int = 0
    id: str = field(
            default_factory=lambda: b64encode(os.urandom(16)).decode()
        )


def parse_cookie_or_default(cookie: bytes | None) -> GameState:
    try:
        cookie = b64decode(cookie)
        state = cc.decrypt(cookie)
        return GameState(**json.loads(state))
    except Exception:
        return GameState()


@app.route("/", methods=["GET"])
def index():
    state = parse_cookie_or_default(request.cookies.get("session"))
    res = make_response(render_template("page.html", state=state))
    res.set_cookie(
        "session", b64encode(
                        cc.encrypt(json.dumps(asdict(state)).encode())
                    ).decode()
    )
    return res


@app.route("/play/<string:user_choice>", methods=["POST"])
def play(user_choice):
    if user_choice not in ["rock", "paper", "scissors"]:
        return "Invalid choice", 400

    server_choice = SystemRandom().choice(["rock", "paper", "scissors"])
    state = parse_cookie_or_default(request.cookies.get("session"))
    print(state)
    state.played += 1

    if server_choice == user_choice:
        state.tied += 1
    elif (
        (user_choice == "rock" and server_choice == "scissors")
        or (user_choice == "paper" and server_choice == "rock")
        or (user_choice == "scissors" and server_choice == "paper")
    ):
        state.won += 1
    else:
        state.lost += 1

    json_res = {"choice": server_choice}
    if state.won == state.played == 100:
        json_res["flag"] = FLAG

    res = app.response_class(
        response=json.dumps(json_res),
        status=200,
        mimetype="application/json"
    )
    res.set_cookie(
        "session", b64encode(
                        cc.encrypt(json.dumps(asdict(state)).encode())
                    ).decode()
    )
    return res


if __name__ == "__main__":
    app.run(port=1337, debug=True)

```

## The Solve?
When I opened the challenge the first time I actually ignored the cookie
cipher completely, noticing that nothing is saving the game state on the
server side: it is completely contained inside the cookie.
\
\
So, this crypto is now a web!
\
\
What we can do is to save our cookie locally and play a round:
* If we win, we save our new cookie and continue playing
* If we lose, we retry with our saved cookie
We can keep this up until we have won 100 games "in a row" and get
the flag without reading a single crypto line.

```python3
import requests

s = requests.Session()

URL = "http://127.0.0.1:1337"

s.get(URL)

saved_cookies = s.cookies.get_dict()['session']

i = 0
while True:
    res = s.post(URL + "/play/paper").json()
    server_choice = res['choice']
    
    if 'flag' in res:
        print(res['flag'])
        exit()
    
    if server_choice == 'rock':
        saved_cookies = s.cookies.get_dict()['session']
        i += 1
    else:
        s = requests.Session()
        s.cookies.set("session", saved_cookies)
```
With this i managed to get the first blood on this challenge .w.

## The Solve
Needless to say, this was a major unintended and soon a v2 of this 
challenge was released with this lines added in the game handling logic:

```python3
if state.played >= 5:
    state = GameState()
```

Ok, so we're not winning this the traditional way, we have to manipulate 
some cookies and actually do crypto :3
\
\
Taking a look at the ChecksummedCipher we see it's AES-GCM with a crc32 
checksum inside the plaintext.
\
\
Despite this being *technically* AES-GCM, the cipher doesn't use nor verify 
any tag, so this really becomes AES-CTR with a cooler name.

This is pretty useful to us since AES-CTR is basically a big xor, and we 
know *most* of the plaintext, but remember, this is applied twice, so 
our final ciphertext will be
$$ \text{ct} = \text{nonce}_b | E_b(\text{nonce}_a) | E_b(E_a(\text{pt})) | E_b(E_a(\text{crc}_a)) | E_b(\text{crc}_b) $$

We don't really care how many times something is encrypted, since we can treat $E_x$ as an otp and therefore 
$$E_x(\text{pt}) \oplus \Delta = E_x(\text{pt} \oplus \Delta) $$

So, let's construct our modified ciphertext!
We can't really modify the nonces in any meaningful way without garbling 
everything, so we're keeping em the same
$$ \text{new\_ct} = \text{nonce}_b | E_b(\text{nonce}_a) $$

Modifying the plaintext is kind of the point, so we can just xor that 
section with the difference between winning and losing pts, call that $\Delta$
$$ \text{new\_ct} = \text{nonce}_b | E_b(\text{nonce}_a) | E_b(E_a(\text{pt})) \oplus \Delta$$

Now AES-CTR will decrypt it to our desired plaintext, but the crc will be wrong!
Luckily, crc is also linear in Z2, specifically:
$$ \text{crc}_a \oplus \text{crc}_b \oplus \text{crc}_c = \text{crc}_{a \oplus b \oplus c} $$

and therefore
$$ \text{crc}_a \oplus \text{crc}_b \oplus \text{crc}_0 = \text{crc}_{a \oplus b} $$
$$ \text{crc}_{\text{pt} \oplus \Delta} = \text{crc}_\text{pt} \oplus \Delta \oplus \text{crc}_0 $$
$$ \text{new\_ct} = \text{nonce}_b | E_b(\text{nonce}_a) | E_b(E_a(\text{pt})) \oplus \Delta | E_b(E_a(\text{crc}_a)) \oplus \text{crc}_\Delta \oplus \text{crc}_0 $$

Now for the last crc we do... nothing! This stems from the fact that
$$ \text{crc}_{x | \text{crc}_x} = 0 $$

Since the first ciphertext is 
$$E_a(\text{pt} | \text{crc}_\text{pt}) = \text{otp}_a \oplus (\text{pt} | \text{crc}_\text{pt})$$

its crc will be
$$ \text{crc}_{\text{otp}_a} \oplus \text{crc}_{\text{pt} | \text{crc}_\text{pt}} \oplus \text{crc}_0 = \text{crc}_{\text{otp}_a} \oplus \text{crc}_0 $$

which depends only on the encryption key of the first cipher, and is therefore constant.
So our winning ciphertext is 
$$ \text{new\_ct} = \text{nonce}_b | E_b(\text{nonce}_a) | E_b(E_a(\text{pt})) \oplus \Delta | E_b(E_a(\text{crc}_a)) \oplus \text{crc}_\Delta \oplus \text{crc}_0 | E_b(\text{crc}_b) $$

Once we have our new cookie we can just keep playing using it as session until we win.

```python3
from base64 import b64decode, b64encode
from zlib import crc32
import requests

URL = "http://127.0.0.1:1337"

xor = lambda a, b: bytes([aa ^ bb for aa, bb in zip(a, b)])

# The id field is a random base64 encoded value that we don't know
# but it's not used, so we just keep it as is
pt =     b'{"won": 0, "tied": 0, "lost": 0, "played": 0, "id": "' 
newpt =  b'{"won": 100,"tied": 0,"lost": 0,"played": 99, "id": "'
pt +=    b'\0' * 24 + b'"}'
newpt += b'\0' * 24 + b'"}'

delta = xor(pt, newpt)
delta += (crc32(delta) ^ crc32(b'\0' * len(delta))).to_bytes(4, 'little')

ct = b64decode(requests.get(URL).cookies['session'])

nonces = ct[:16]
enc_data = ct[16:]

new_enc_data = xor(enc_data, delta + b'\0' * 128)

session = b64encode(nonces + new_enc_data).decode()

res = requests.post(URL + '/play/rock',
                        cookies={"session":session}
                    ).json()
while 'flag' not in res:
    res = requests.post(URL + '/play/rock',
                            cookies={"session":session}
                        ).json()
print(res['flag'])
```