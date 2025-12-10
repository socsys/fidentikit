import logging
import requests
from typing import Any
from urllib.parse import urlparse
from requests.exceptions import RequestException
from common.modules.browser.browser import RequestsBrowser

logger = logging.getLogger(__name__)


class MetadataDetector:

    def __init__(self, config: dict, result: dict):
        self.config = config
        self.result = result

        self.resolved_url = result["resolved"]["url"]
        self.parsed_url = urlparse(self.resolved_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"

    def start(self):
        logger.info(f"Starting metadata detection for domain: {self.base_url}")

        s = RequestsBrowser.chrome_session()

        self.result["metadata_data"] = {
            "robots_txt": self.request(s,
                f"{self.base_url}/robots.txt",
                statuscode=200,
                mime="text/plain",
                parsejson=False
            ),
            "security_txt": self.request(s,
                f"{self.base_url}/.well-known/security.txt",
                statuscode=200,
                mime="text/plain",
                parsejson=False
            ),
            "webfinger": self.request(s,
                f"{self.base_url}/.well-known/webfinger?resource=acct%3Aalice%40gmail.com&rel=http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer",
                statuscode=200,
                mime="application/jrd+json",
                parsejson=True
            ),
            "openid_configuration": self.request(s,
                f"{self.base_url}/.well-known/openid-configuration",
                statuscode=200,
                mime="application/json",
                parsejson=True
            ),
            "oauth_authorization_server": self.request(s,
                f"{self.base_url}/.well-known/oauth-authorization-server",
                statuscode=200,
                mime="application/json",
                parsejson=True
            ),
            "oauth_client": self.request(s,
                f"{self.base_url}/.well-known/oauth-client",
                statuscode=200,
                mime="application/json",
                parsejson=True
            ),
            "web_identity": self.request(s,
                f"{self.base_url}/.well-known/web-identity",
                statuscode=200,
                mime="application/json",
                parsejson=True
            ),
            "browserid": self.request(s,
                f"{self.base_url}/.well-known/browserid",
                statuscode=200,
                mime="application/json",
                parsejson=True
            ),
            "jwks": self.request(s,
                f"{self.base_url}/.well-known/jwks.json",
                statuscode=200,
                mime=None,
                parsejson=True
            ),
            "uma2_configuration": self.request(s,
                f"{self.base_url}/.well-known/uma2-configuration",
                statuscode=200,
                mime=None,
                parsejson=True
            ),
            "fido_configuration": self.request(s,
                f"{self.base_url}/.well-known/fido-configuration",
                statuscode=200,
                mime=None,
                parsejson=True
            ),
            "fido_2fa_configuration": self.request(s,
                f"{self.base_url}/.well-known/fido-2fa-configuration",
                statuscode=200,
                mime=None,
                parsejson=True
            ),
            "fido2_configuration": self.request(s,
                f"{self.base_url}/.well-known/fido2-configuration",
                statuscode=200,
                mime=None,
                parsejson=True
            ),
            "apple_app_site_association": self.request(s,
                f"{self.base_url}/.well-known/apple-app-site-association",
                statuscode=200,
                mime=None,
                parsejson=True
            ),
            "assetlinks": self.request(s,
                f"{self.base_url}/.well-known/assetlinks.json",
                statuscode=200,
                mime="application/json",
                parsejson=True
            ),
            "passkey_endpoints": self.request(s,
                f"{self.base_url}/.well-known/passkey-endpoints",
                statuscode=200,
                mime="application/json",
                parsejson=True
            )
        }

        self.result["metadata_available"] = {}
        for k, v in self.result["metadata_data"].items():
            self.result["metadata_available"][k] = True if v else False

    @staticmethod
    def request(
        session: requests.Session,
        url: str,
        timeout: float = 10,
        statuscode: int = 200,
        mime: str = "application/json",
        parsejson: bool = True
    ) -> None|str|Any:
        try:
            logger.info(f"Metadata detection request: {url}")
            r = session.get(url, timeout=timeout)
            if statuscode and r.status_code != statuscode:
                logger.info(f"Invalid status code ({r.status_code} != {statuscode}) while requesting: {url}")
                return None
            if mime and mime not in r.headers.get("Content-Type", ""):
                logger.info(f"Invalid mime type ({r.headers.get('Content-Type')} != {mime}) while requesting: {url}")
                return None
            if parsejson:
                return r.json()
            else:
                return r.text
        except RequestException as e:
            logger.info(f"RequestException while requesting: {url}")
            logger.debug(e)
            return None
        except Exception as e:
            logger.info(f"Exception while requesting: {url}")
            logger.debug(e)
            return None

