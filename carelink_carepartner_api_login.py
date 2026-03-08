###############################################################################
#
#  Carelink Carepartner API login
#
#  Description:
#
#    This program performs the login procedure to the Medtronic Carelink Cloud
#    service as implemeted in the Carlink Connect app. On successfull login it
#    creates a json file with the resulting login data. The file contains:
#    - access_token
#    - refresh_token
#    - scope
#    - client_id
#    - client_secret
#    - mag-identifier
#
#  Author:
#
#    The original code has been implemented by @palmarci (Pal Marci)
#
#  Changelog:
#
#    28/12/2023 - Initial version
#    14/03/2025 - Updated discovery_url, based on PR#23
#    19/11/2024 - Update discovery_url
#
#
#  Dependencies:
#
#     This script needs the following additional Python packages:
#     - curlify
#     - OpenSSL
#     - selenium-wire
#
###############################################################################

import argparse
import base64
import hashlib
import json
import logging
import os
import random
import re
import secrets
import string
import uuid
from http.client import HTTPConnection
from time import sleep
from urllib.parse import parse_qs, urlparse

import curlify
import OpenSSL
import requests
from selenium.common.exceptions import WebDriverException
from seleniumwire import webdriver


def setup_logging():
    HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def random_b64_str(length):
    random_chars = "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(length + 10)
    )
    base64_string = base64.b64encode(random_chars.encode("utf-8")).decode("utf-8")
    return base64_string[:length]


def random_uuid():
    return str(uuid.UUID(bytes=secrets.token_bytes(16)))


def random_android_model():
    models = ["SM-G973F", "SM-G988U1", "SM-G981W", "SM-G9600"]
    random.shuffle(models)
    return models[0]


def random_device_id():
    return hashlib.sha256(os.urandom(40)).hexdigest()


def create_csr(keypair, cn, ou, dc, o):
    req = OpenSSL.crypto.X509Req()

    # order is not checked
    req.get_subject().CN = cn
    req.get_subject().OU = ou
    req.get_subject().DC = dc
    req.get_subject().O = o

    req.set_pubkey(keypair)
    req.sign(keypair, "sha256")

    csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)
    return csr


def reformat_csr(csr):
    # remove footer & header, re-encode with url safe base64
    csr = csr.decode()
    csr = csr.replace("\n", "")
    csr = csr.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
    csr = csr.replace("-----END CERTIFICATE REQUEST-----", "")

    csr_raw = base64.b64decode(csr.encode())
    csr = base64.urlsafe_b64encode(csr_raw).decode()
    return csr


def parse_oauth_code_and_state(location):
    query = parse_qs(urlparse(location).query)
    code = query.get("code", [None])[0]
    state = query.get("state", [None])[0]
    return code, state


def do_captcha(url, redirect_url):
    print("opening Firefox instance...")
    print(
        "Warning: you may need to close Firefox if it's already running or nothing happens!"
    )

    driver = webdriver.Firefox()
    try:
        driver.get(url)

        while True:
            for request in driver.requests:
                if not request.response:
                    continue

                if request.response.status_code != 302:
                    continue

                location = request.response.headers.get("location")
                if not location or redirect_url not in location:
                    continue

                code, state = parse_oauth_code_and_state(location)
                if code is None:
                    raise Exception(f"Missing OAuth code in redirect: {location}")

                driver.quit()
                return code, state

            sleep(0.1)
    except WebDriverException as ex:
        raise Exception(f"Browser login failed: {ex}") from ex
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def resolve_endpoint_config(discovery_url, is_us_region=False):
    discover_resp = json.loads(requests.get(discovery_url).text)
    sso_url = None
    is_auth0 = False

    for region_config in discover_resp["CP"]:
        region = region_config["region"].lower()
        if is_us_region and region != "us":
            continue
        if not is_us_region and region != "eu":
            continue

        key = region_config.get("UseSSOConfiguration")
        if not key:
            key = "SSOConfiguration"

        sso_url = region_config.get(key)
        is_auth0 = "auth0" in key.lower()
        break

    if sso_url is None:
        raise Exception("Could not get SSO config url")

    sso_config = json.loads(requests.get(sso_url).text)
    api_base_url = (
        f"https://{sso_config['server']['hostname']}:"
        f"{sso_config['server']['port']}/{sso_config['server']['prefix']}"
    )
    if api_base_url.endswith("/"):
        api_base_url = api_base_url[:-1]

    return sso_config, api_base_url, is_auth0


def write_datafile(obj, filename):
    print("wrote data file")
    with open(filename, "w", encoding="utf-8") as file_obj:
        json.dump(obj, file_obj, indent=4)


def do_login_non_auth0(endpoint_config):
    sso_config, api_base_url, _ = endpoint_config

    # step 1 initialize
    data = {
        "client_id": sso_config["oauth"]["client"]["client_ids"][0]["client_id"],
        "nonce": random_uuid(),
    }
    headers = {
        "device-id": base64.b64encode(random_device_id().encode()).decode()
    }
    client_init_url = (
        api_base_url + sso_config["mag"]["system_endpoints"]["client_credential_init_endpoint_path"]
    )
    client_init_req = requests.post(client_init_url, data=data, headers=headers)
    client_init_response = json.loads(client_init_req.text)

    # step 2 authorize
    client_code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
    client_code_verifier = re.sub("[^a-zA-Z0-9]+", "", client_code_verifier)
    client_code_challenge = hashlib.sha256(client_code_verifier.encode("utf-8")).digest()
    client_code_challenge = base64.urlsafe_b64encode(client_code_challenge).decode("utf-8")
    client_code_challenge = client_code_challenge.replace("=", "")

    client_state = random_b64_str(22)
    auth_params = {
        "client_id": client_init_response["client_id"],
        "response_type": "code",
        "display": "social_login",
        "scope": sso_config["oauth"]["client"]["client_ids"][0]["scope"],
        "redirect_uri": sso_config["oauth"]["client"]["client_ids"][0]["redirect_uri"],
        "code_challenge": client_code_challenge,
        "code_challenge_method": "S256",
        "state": client_state,
    }
    authorize_url = (
        api_base_url + sso_config["oauth"]["system_endpoints"]["authorization_endpoint_path"]
    )
    providers = json.loads(requests.get(authorize_url, params=auth_params).text)
    captcha_url = providers["providers"][0]["provider"]["auth_url"]

    # step 3 captcha login and consent
    print(f"captcha url: {captcha_url}")
    captcha_code, captcha_sso_state = do_captcha(
        captcha_url, sso_config["oauth"]["client"]["client_ids"][0]["redirect_uri"]
    )
    if captcha_sso_state and captcha_sso_state != client_state:
        raise Exception("SSO state mismatch after captcha")
    print(f"sso state after captcha: {captcha_sso_state}")

    # step 4 registration
    register_device_id = random_device_id()
    client_auth_str = (
        f"{client_init_response['client_id']}:{client_init_response['client_secret']}"
    )

    android_model = random_android_model()
    android_model_safe = re.sub(r"[^a-zA-Z0-9]", "", android_model)
    keypair = OpenSSL.crypto.PKey()

    # ignoring sso_config['mag']['mobile_sdk']['client_cert_rsa_keybits'],
    # due to app minimum size clamp to 2048.
    keypair.generate_key(OpenSSL.crypto.TYPE_RSA, rsa_keysize)
    csr = create_csr(
        keypair,
        "socialLogin",
        register_device_id,
        android_model_safe,
        sso_config["oauth"]["client"]["organization"],
    )

    reg_headers = {
        "device-name": base64.b64encode(android_model.encode()).decode(),
        "authorization": f"Bearer {captcha_code}",
        "cert-format": "pem",
        "client-authorization": "Basic " + base64.b64encode(client_auth_str.encode()).decode(),
        "create-session": "true",
        "code-verifier": client_code_verifier,
        "device-id": base64.b64encode(register_device_id.encode()).decode(),
        "redirect-uri": sso_config["oauth"]["client"]["client_ids"][0]["redirect_uri"],
    }
    csr = reformat_csr(csr)
    reg_url = api_base_url + sso_config["mag"]["system_endpoints"]["device_register_endpoint_path"]
    reg_req = requests.post(reg_url, headers=reg_headers, data=csr)
    if reg_req.status_code != 200:
        print(f"\n\n{curlify.to_curl(reg_req.request)}")
        try:
            err_desc = json.loads(reg_req.text).get("error_description", reg_req.text)
        except json.JSONDecodeError:
            err_desc = reg_req.text
        raise Exception(f"Could not register: {err_desc}")

    # step 5 token
    token_req_url = api_base_url + sso_config["oauth"]["system_endpoints"]["token_endpoint_path"]
    token_req_data = {
        "assertion": reg_req.headers["id-token"],
        "client_id": client_init_response["client_id"],
        "client_secret": client_init_response["client_secret"],
        "scope": sso_config["oauth"]["client"]["client_ids"][0]["scope"],
        "grant_type": reg_req.headers["id-token-type"],
    }
    token_req = requests.post(
        token_req_url,
        headers={"mag-identifier": reg_req.headers["mag-identifier"]},
        data=token_req_data,
    )
    if token_req.status_code != 200:
        print(f"\n\n{curlify.to_curl(token_req.request)}")
        raise Exception("Could not get token data")

    token_data = json.loads(token_req.text)
    print("got token data from server")

    token_data["client_id"] = token_req_data["client_id"]
    token_data["client_secret"] = token_req_data["client_secret"]
    token_data.pop("expires_in", None)
    token_data.pop("token_type", None)
    token_data["mag-identifier"] = reg_req.headers["mag-identifier"]

    write_datafile(token_data, logindata_file)
    return token_data


def do_login_auth0(endpoint_config):
    sso_config, api_base_url, _ = endpoint_config

    auth_params = {
        "client_id": sso_config["client"]["client_id"],
        "response_type": "code",
        "scope": sso_config["client"]["scope"],
        "redirect_uri": sso_config["client"]["redirect_uri"],
        "audience": sso_config["client"]["audience"],
    }
    authorize_url = api_base_url + sso_config["system_endpoints"]["authorization_endpoint_path"]
    auth_query = "&".join(f"{key}={value}" for key, value in auth_params.items())
    captcha_url = f"{authorize_url}?{auth_query}"
    captcha_code, _ = do_captcha(captcha_url, sso_config["client"]["redirect_uri"])

    token_req_url = api_base_url + sso_config["system_endpoints"]["token_endpoint_path"]
    token_req_data = {
        "grant_type": "authorization_code",
        "client_id": sso_config["client"]["client_id"],
        "code": captcha_code,
        "redirect_uri": sso_config["client"]["redirect_uri"],
    }
    token_req = requests.post(token_req_url, data=token_req_data)
    if token_req.status_code != 200:
        print(f"\n\n{curlify.to_curl(token_req.request)}")
        print(token_req.text)
        raise Exception("Could not get token data")

    token_data = json.loads(token_req.text)
    print("got token data from server")

    token_data["client_id"] = token_req_data["client_id"]
    token_data.pop("expires_in", None)
    token_data.pop("token_type", None)
    token_data["client_secret"] = token_req_data.get("client_secret", "")
    token_data["scope"] = token_data.get("scope", sso_config["client"]["scope"])
    if "mag-identifier" not in token_data and token_req.headers.get("mag-identifier"):
        token_data["mag-identifier"] = token_req.headers["mag-identifier"]

    write_datafile(token_data, logindata_file)
    return token_data


def do_login(endpoint_config):
    _, _, is_auth0 = endpoint_config

    if is_auth0:
        return do_login_auth0(endpoint_config)
    return do_login_non_auth0(endpoint_config)


def read_data_file(file):
    token_data = None
    if os.path.isfile(file):
        try:
            with open(file, "r", encoding="utf-8") as file_obj:
                token_data = json.loads(file_obj.read())
        except json.JSONDecodeError:
            print("failed parsing json")

        if token_data is not None:
            required_fields = [
                "access_token",
                "refresh_token",
                "scope",
                "client_id",
                "client_secret",
                "mag-identifier",
            ]
            for field in required_fields:
                if field not in token_data:
                    print(f"field {field} is missing from data file")
                    return None
    return token_data


# config
is_debug = False
logindata_file = "logindata.json"
discovery_url = "https://clcloud.minimed.eu/connect/carepartner/v13/discover/android/3.6"
rsa_keysize = 2048


def main(is_us_region):
    if is_debug:
        setup_logging()

    token_data = read_data_file(logindata_file)

    if token_data is None:
        print("performing login...")
        endpoint_config = resolve_endpoint_config(discovery_url, is_us_region=is_us_region)
        do_login(endpoint_config)
    else:
        print("token data file already exists")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--us", help="Specify US region", default=False, action="store_true")
    args = parser.parse_args()

    main(args.us)
