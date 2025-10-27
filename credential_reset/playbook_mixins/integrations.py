from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
from common.utils import generate_timestamp
from sonicos.api import get_request


class IntegrationsMixin():
    """Mixin class to add cloud/integration-related methods to the main playbook class."""
    # Check AWS API status (log/aws)
    def check_aws_api(self):
        if should_run_check('aws_api', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    aws_api = self.alt_session.get_aws_api()
                else:
                    aws_api = get_request(self.api_base, self.api_session, '/api/sonicos/log/aws', silent=self.silent)

                if aws_api:
                    aws_enabled = aws_api.get('log', {}).get('aws', {}).get('enable', False)
                    if aws_enabled:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: AWS API is enabled. Please update the secret key.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: AWS API is not enabled.")

                    update_routine_results(self.routine_results, self.firewall, 'aws_api', aws_api)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No AWS API information found")
                        print(type(aws_api), "->", aws_api)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving AWS API information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping AWS API check (severity: {get_check_severity('aws_api')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['aws_api'])

    # Cloud Secure Edge (CSE)
    def check_cloud_secure_edge(self):
        if should_run_check('cloud_secure_edge', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is not available on GEN6 firewalls.")
                    cse_info = None
                else:
                    cse_info = get_request(self.api_base, self.api_session, '/api/sonicos/cloud-secure-edge/base', silent=self.silent)

                if cse_info:
                    cse_enabled = cse_info.get('cloud_secure_edge', {}).get('created', False)
                    if cse_enabled:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is enabled. Reset the Cloud Secure Edge connector authentication key.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is not enabled.")

                    update_routine_results(self.routine_results, self.firewall, 'cse_info', cse_info)
                else:
                    if self.firewall_info['firewall_generation'] == 6:
                        pass
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No CSE information found")
                            print(type(cse_info), "->", cse_info)
                            print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving CSE information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Cloud Secure Edge (CSE) check (severity: {get_check_severity('cloud_secure_edge')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['cloud_secure_edge'])

