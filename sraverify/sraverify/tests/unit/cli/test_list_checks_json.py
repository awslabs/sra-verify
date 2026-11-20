import json

import pytest

from sraverify import cli, scanner
from sraverify.core.registry import all_checks


def test_json_catalog_exports_registry_metadata_without_an_aws_session(monkeypatch, capsys):
    def unexpected_session(**kwargs):
        pytest.fail('JSON catalog must not initialize an AWS session')

    monkeypatch.setattr(scanner, 'get_session', unexpected_session)

    assert cli.main(['--list-checks', '--format', 'json']) == 0

    output = capsys.readouterr()
    assert not output.err
    catalog = json.loads(output.out)
    assert set(catalog) == {'schema_version', 'checks'}
    assert catalog['schema_version'] == 1
    meta = all_checks()['SRA-SECURITYHUB-21'].meta
    check = next(row for row in catalog['checks'] if row['check_id'] == meta.check_id)
    assert check == {
        'check_id': 'SRA-SECURITYHUB-21',
        'title': meta.title,
        'description': meta.description,
        'service': 'Security Hub CSPM',
        'account_type': 'audit',
        'severity': meta.severity.value,
        'resource_type': 'AWS::SecurityHub::FindingAggregator',
        'sra_sections': ['Security Tooling account', 'AWS Security Hub CSPM'],
        'additional_urls': list(meta.additional_urls),
    }


@pytest.mark.parametrize('account_type', ['all', 'audit'])
def test_json_catalog_matches_text_order_and_account_filter(monkeypatch, capsys, account_type):
    monkeypatch.setattr(scanner, 'get_session', lambda **kwargs: object())
    args = ['--list-checks', '--account-type', account_type]

    assert cli.main(args) == 0
    text = capsys.readouterr().out
    assert cli.main([*args, '--format', 'json']) == 0
    catalog = json.loads(capsys.readouterr().out)

    expected = [line.strip().split(':', 1)[0] for line in text.splitlines()[1:]]
    assert expected
    assert [row['check_id'] for row in catalog['checks']] == expected
    assert expected == sorted(expected)
    if account_type != 'all':
        assert {row['account_type'] for row in catalog['checks']} == {account_type}


def test_explicit_text_format_preserves_default_listing(monkeypatch, capsys):
    monkeypatch.setattr(scanner, 'get_session', lambda **kwargs: object())

    assert cli.main(['--list-checks']) == 0
    default = capsys.readouterr().out
    assert cli.main(['--list-checks', '--format', 'text']) == 0
    assert capsys.readouterr().out == default


@pytest.mark.parametrize('args', [['--format', 'json'], ['--list-services', '--format', 'text']])
def test_catalog_format_requires_list_checks(capsys, args):
    with pytest.raises(SystemExit) as exc:
        cli.main(args)

    assert exc.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert '--format requires --list-checks' in output.err
