

# Helper function for the summary
def calculate_routine_statistics(routine_results: dict, firewall: str):
    """Calculate and update routine statistics."""
    try:
        routine_results[firewall]['total_users_forced_to_update_password'] = len([u for u in routine_results[firewall].get('users', []) if u.get('commit_successful') is True])
    except (KeyError, TypeError):
        routine_results[firewall]['total_users_forced_to_update_password'] = 0

    try:
        routine_results[firewall]['commit_possibly_failed_count'] = len([u for u in routine_results[firewall].get('users', []) if u.get('commit_successful') is False])
    except (KeyError, TypeError):
        routine_results[firewall]['commit_possibly_failed_count'] = 0

    try:
        routine_results[firewall]['skipped_user_count'] = len([u for u in routine_results[firewall].get('users', []) if u.get('skipped') is True])
    except (KeyError, TypeError):
        routine_results[firewall]['skipped_user_count'] = 0

    try:
        routine_results[firewall]['total_postprocess_user_count'] = len(routine_results[firewall].get('users', []))
    except (KeyError, TypeError):
        routine_results[firewall]['total_postprocess_user_count'] = 0

    routine_results[firewall]['completed_routine_successfully'] = True


