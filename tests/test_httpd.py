import json
import requests
import http.client as via

r = requests.get("http://127.0.0.1/")
assert r.content.decode() == "<html><body></body></html>"

payload = {'key1': 'value1', 'key2': 'value2'}
r = requests.post("http://127.0.0.1/", data=json.dumps(payload))
assert json.loads(r.content)["message"] == "ok"

proxies = {
    'http':'http://localhost',
    'https':'http://localhost'
}
via.HTTPConnection._http_vsn_str = 'HTTP/1.0'
r = requests.get('http://www.google.com/', proxies = proxies)
assert r.content.decode() == "<html><body></body></html>"

r = requests.get('http://azenv.net', proxies = proxies)
assert r.content.decode().find("AZ Environment") != -1

r = requests.get('http://wfuchs.de/azenv.php', proxies = proxies, allow_redirects=False)
assert r.content.decode().find("Moved Permanently") != -1

#r = requests.get('https://www.google.com', proxies = proxies, verify=False)
#assert r.content.decode() == "<html><body></body></html>"
