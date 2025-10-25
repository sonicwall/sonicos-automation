from typing import List, Optional
from common.utils import generate_timestamp
from credential_reset.firewall import FirewallTarget
from credential_reset.utils import normalize_boolean, normalize_password, normalize_temp_password
import csv


def parse_csv_targets(filepath: str, silent: bool = False) -> List[FirewallTarget]:
    """Parse CSV file and return list of FirewallTarget objects."""
    targets = []

    try:
        with open(filepath, 'r') as f:
            # Try to detect if there's a header by checking the first line
            first_line = f.readline().strip()
            f.seek(0)  # Reset file pointer

            # If first line contains header keywords, use DictReader
            if "target_fw" in first_line.lower() or "admin_user" in first_line.lower():
                reader = csv.DictReader(f)
                for row_num, row in enumerate(reader, start=2):  # Start at 2 since header is line 1
                    target = _parse_csv_row_dict(row, row_num, silent=silent)
                    if target:
                        targets.append(target)
            else:
                # No header, treat as raw CSV with expected column order
                reader = csv.reader(f)
                for row_num, row in enumerate(reader, start=1):
                    target = _parse_csv_row_list(row, row_num)
                    if target:
                        targets.append(target)

    except Exception as err:
        print(f"{generate_timestamp()}: Error opening/parsing CSV file: {err}")
        exit(1)

    return targets


def _parse_csv_row_dict(row: dict, row_num: int, silent: bool = False) -> Optional[FirewallTarget]:
    """Parse a CSV row when using DictReader (with headers)."""
    firewall = row.get('target_fw', '').strip()

    # Skip comments, empty rows, or invalid entries
    if not firewall or firewall.startswith('#'):
        return None

    if not row.get('admin_user'):
        print(f"{generate_timestamp()}: Warning: Row {row_num} missing admin_user, skipping")
        return None

    return FirewallTarget(
        firewall=firewall,
        username=row.get('admin_user', '').strip() or None,
        password=normalize_password(row.get('admin_password', '')),
        sshport=row.get('target_ssh_mgmt_port', '22').strip() or '22',
        temp_password=normalize_temp_password(password=row.get('temporary_password', ''),
                                              randomize=normalize_boolean(row.get('randomize_temp_password', 'false')),
                                              silent=silent),
        randomize_temp_password=normalize_boolean(row.get('randomize_temp_password', '')),
        unbind_totp=normalize_boolean(row.get('unbind_totp', '')),
        force_password_change=normalize_boolean(row.get('force_password_change', ''))
    )


def _parse_csv_row_list(row: List[str], row_num: int) -> Optional[FirewallTarget]:
    """Parse a CSV row when using regular reader (no headers)."""
    if not row or len(row) == 0:
        return None

    # Skip comments
    if row[0].strip().startswith('#'):
        return None

    # Ensure we have at least firewall and username
    if len(row) < 2:
        print(f"{generate_timestamp()}: Warning: Row {row_num} has insufficient columns, skipping")
        return None

    # Pad row with empty strings if needed (backwards compatibility)
    while len(row) < 8:
        row.append('')

    firewall = row[0].strip()
    if not firewall:
        return None

    return FirewallTarget(
        firewall=firewall,
        username=row[1].strip() or None,
        password=normalize_password(row[2]),
        sshport=row[3].strip() or '22',
        temp_password=normalize_temp_password(password=row[4],
                                              randomize=normalize_boolean(row[7])),
        randomize_temp_password=normalize_boolean(row[7]),
        unbind_totp=normalize_boolean(row[5]),
        force_password_change=normalize_boolean(row[6])
    )
