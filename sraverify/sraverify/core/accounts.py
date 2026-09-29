"""
Organizations account lifecycle helpers.

AWS Organizations added an account ``State`` field to ``DescribeAccount``,
``ListAccounts``, ``ListAccountsForParent`` and ``ListDelegatedAdministrators``
and is retiring the older ``Status`` field. The botocore model (1.43.105) dates
the retirement to September 9, 2026; the test organization was still returning
both fields on 2026-09-29. Every check that filters an organization's account
list to active accounts goes through :func:`is_active_account`, so the switch
is made in one place rather than at each call site.
"""
from collections.abc import Mapping
from typing import Any

ACCOUNT_ACTIVE = "ACTIVE"


def is_active_account(account: Mapping[str, Any]) -> bool:
    """
    Return ``True`` when an Organizations ``Account`` object is active.

    ``State`` is authoritative whenever AWS returns it: it has a finer lifecycle
    (``PENDING_ACTIVATION``, ``ACTIVE``, ``SUSPENDED``, ``PENDING_CLOSURE``,
    ``CLOSED``) than ``Status``, so an account whose ``State`` is not ``ACTIVE``
    is not active even if a stale ``Status`` still says it is. ``Status`` is
    read only when ``State`` is absent, which covers responses from before the
    field existed and test fixtures that predate it.

    Args:
        account: One element of an Organizations ``Accounts`` list.

    Returns:
        ``True`` if the account is active, ``False`` otherwise.
    """
    state = account.get("State")
    if state is not None:
        return state == ACCOUNT_ACTIVE
    return account.get("Status") == ACCOUNT_ACTIVE
