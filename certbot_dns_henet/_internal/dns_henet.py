"""DNS Authenticator for Huricane Electric DNS."""
import logging
from typing import Any
from typing import Callable
from typing import Optional

from lexicon.client import Client
from requests import HTTPError, RequestException

from certbot import errors, configuration
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

APIKEY_URL = "https://dyn.dns.he.net/nic/update"


class Authenticator(dns_common_lexicon.LexiconDNSAuthenticator):
    """
        DNS Authenticator for Huricane Electric DNS.
        This Authenticator uses the Huricane Electric API to fulfill a dns-01 challenge.
    """

    def more_info(self) -> str:  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' \
               'the Huricane Electric API.'

    def __init__(self, config: configuration.NamespaceConfig, name: str):
        super().__init__(config, name)
        pass

    def _provider_name(self) -> str:
        return "henet"

    def _ttl(self) -> int:
        return 300

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        try:
            resolved_domain = self._resolve_domain(domain)
        except errors.PluginError as e:
            logger.debug('Encountered error finding domain_id during deletion: %s', e,
                         exc_info=True)
            return

        try:
            with Client(self._build_lexicon_config(resolved_domain)) as operations:
                operations.update_record(rtype="TXT", name=validation_name, content="EMPTY")
        except RequestException as e:
            logger.debug('Encountered error clean up TXT record: %s', e, exc_info=True)

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        resolved_domain = self._resolve_domain(domain)

        try:
            with Client(self._build_lexicon_config(resolved_domain)) as operations:
                operations.update_record(rtype='TXT', name=validation_name, content=validation)
        except RequestException as e:
            logger.debug('Encountered error update TXT record: %s', e, exc_info=True)
            raise errors.PluginError('Error update TXT record: {0}'.format(e))
