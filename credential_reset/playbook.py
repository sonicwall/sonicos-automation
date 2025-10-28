from common.utils import generate_timestamp
from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
from sonicos.api import (
    get_request,
    post_request,
    put_request,
    patch_request,
    commit_pending,
    logout,
    disable_sonicos_api_ssh,
    get_ssh_session,
    get_users_ssh,
    force_password_change_ssh,
    post_request_direct_cli,
)
from credential_reset.playbook_mixins.authentication import AuthenticationMixin
from credential_reset.playbook_mixins.integrations import IntegrationsMixin
from credential_reset.playbook_mixins.infrastructure import InfrastructureMixin
from credential_reset.playbook_mixins.monitoring import MonitoringMixin
from credential_reset.playbook_mixins.networking import NetworkingMixin
from credential_reset.playbook_mixins.vpn import VPNMixin
from credential_reset.playbook_mixins.wireless import WirelessMixin


# Playbook Class
class Playbook(AuthenticationMixin,
               IntegrationsMixin,
               InfrastructureMixin,
               MonitoringMixin,
               NetworkingMixin,
               VPNMixin,
               WirelessMixin):
    def __init__(self,
                 target,
                 target_numbers=None,
                 silent=False,
                 api_base=None,
                 alt_session=None,
                 api_session=None,
                 args=None,
                 routine_results=None,
                 firewall_info=None
                 ):
        self.target = target
        self.target_numbers = target_numbers
        self.silent = silent
        self.api_base = api_base
        self.alt_session = alt_session
        self.api_session = api_session
        self.a = args
        self.firewall = target.firewall
        self.routine_results = routine_results
        self.firewall_info = firewall_info

    # Setter/Getter for api_session.
    def set_api_session(self, api_session):
        self.api_session = api_session
    def get_api_session(self):
        return self.api_session

    # Setter/Getter for alt_session.
    def set_alt_session(self, alt_session):
        self.alt_session = alt_session
    def get_alt_session(self):
        return self.alt_session

    # Return latest routine results
    def get_routine_results(self):
        return self.routine_results

    # Replace routine results
    def set_routine_results(self, routine_results):
        self.routine_results = routine_results
