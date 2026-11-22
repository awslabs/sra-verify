from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import Stubber

from sraverify.services.config.client import ConfigClient


CASES = [
    ("describe_configuration_aggregators", "ConfigurationAggregators", (), {},
     {"ConfigurationAggregatorName": "first"}, {"ConfigurationAggregatorName": "second"}),
    ("describe_configuration_aggregator_sources_status", "AggregatedSourceStatusList",
     ("example",), {"ConfigurationAggregatorName": "example"},
     {"SourceId": "111122223333", "LastUpdateStatus": "SUCCEEDED"},
     {"SourceId": "111122223333", "LastUpdateStatus": "FAILED"}),
]


@pytest.fixture
def client():
    wrapper = ConfigClient.__new__(ConfigClient)
    wrapper.region = "us-east-1"
    wrapper.client = boto3.client("config", region_name="us-east-1", aws_access_key_id="test", aws_secret_access_key="test")
    return wrapper


@pytest.mark.parametrize("method,key,args,params,first,second", CASES)
def test_two_pages(client, method, key, args, params, first, second):
    with Stubber(client.client) as stub:
        stub.add_response(method, {key: [first], "NextToken": "next"}, params)
        stub.add_response(method, {key: [second]}, {**params, "NextToken": "next"})
        assert getattr(client, method)(*args) == {key: [first, second]}
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("method,key,args,params,first,second", CASES)
@pytest.mark.parametrize("bad", [None, {}, ["invalid"]])
def test_malformed_second_page_raises(client, method, key, args, params, first, second, bad):
    page = bad if bad is None else {key: bad}
    client.client = Mock()
    client.client.get_paginator.return_value.paginate.return_value = [{key: [first]}, page]
    with pytest.raises(TypeError):
        getattr(client, method)(*args)


@pytest.mark.parametrize("method,key,args,params,first,second", CASES)
def test_missing_list_advances(client, method, key, args, params, first, second):
    with Stubber(client.client) as stub:
        stub.add_response(method, {"NextToken": "next"}, params)
        stub.add_response(method, {key: [second]}, {**params, "NextToken": "next"})
        assert getattr(client, method)(*args) == {key: [second]}
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("method,key,args,params,first,second", CASES)
def test_second_page_error_discards_first(client, method, key, args, params, first, second):
    with Stubber(client.client) as stub:
        stub.add_response(method, {key: [first], "NextToken": "next"}, params)
        stub.add_client_error(method, service_error_code="AccessDeniedException", service_message="denied", expected_params={**params, "NextToken": "next"})
        result = getattr(client, method)(*args)
        assert result == {"Error": {"Code": "AccessDeniedException", "Message": "denied", "Operation": "".join(x.title() for x in method.split("_"))}}
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("method,key,args,params,first,second", CASES)
def test_repeated_token_discards_pages(client, method, key, args, params, first, second):
    with Stubber(client.client) as stub:
        stub.add_response(method, {key: [first], "NextToken": "next"}, params)
        stub.add_response(method, {key: [second], "NextToken": "next"}, {**params, "NextToken": "next"})
        result = getattr(client, method)(*args)
        assert set(result) == {"Error"}
        assert result["Error"]["Code"] == "PaginationError"
        assert result["Error"]["Operation"] == "Request"
        stub.assert_no_pending_responses()


def test_accessor_retries_error_and_caches_full_result(client):
    from sraverify.core.scan_context import ScanContext
    from sraverify.services.config.base import ConfigCheck

    class ConcreteCheck(ConfigCheck):
        def execute(self):
            pass

    check = ConcreteCheck.__new__(ConcreteCheck)
    check._ctx = ScanContext(boto3.Session(region_name="us-east-1"))
    check._clients = {"us-east-1": client}
    first = {"ConfigurationAggregatorName": "first"}
    second = {"ConfigurationAggregatorName": "second"}
    with Stubber(client.client) as stub:
        stub.add_response("describe_configuration_aggregators", {"ConfigurationAggregators": [first], "NextToken": "next"}, {})
        stub.add_client_error("describe_configuration_aggregators", service_error_code="AccessDeniedException", expected_params={"NextToken": "next"})
        stub.add_response("describe_configuration_aggregators", {"ConfigurationAggregators": [first], "NextToken": "next"}, {})
        stub.add_response("describe_configuration_aggregators", {"ConfigurationAggregators": [second]}, {"NextToken": "next"})
        assert "Error" in check.get_configuration_aggregators("us-east-1")
        expected = {"ConfigurationAggregators": [first, second]}
        assert check.get_configuration_aggregators("us-east-1") == expected
        assert check.get_configuration_aggregators("us-east-1") == expected
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("bad", [None, {}, ["invalid"]])
def test_accessor_retries_malformed_page(client, bad):
    from sraverify.core.scan_context import ScanContext
    from sraverify.services.config.base import ConfigCheck

    class ConcreteCheck(ConfigCheck):
        def execute(self):
            pass

    check = ConcreteCheck.__new__(ConcreteCheck)
    check._ctx = ScanContext(boto3.Session(region_name="us-east-1"))
    check._clients = {"us-east-1": client}
    key = "ConfigurationAggregators"
    page = bad if bad is None else {key: bad}
    client.client = Mock()
    client.client.get_paginator.return_value.paginate.side_effect = [
        [{key: [{"ConfigurationAggregatorName": "first"}]}, page],
        [{key: [{"ConfigurationAggregatorName": "second"}]}],
    ]
    with pytest.raises(TypeError):
        check.get_configuration_aggregators("us-east-1")
    assert check.get_configuration_aggregators("us-east-1") == {key: [{"ConfigurationAggregatorName": "second"}]}


@pytest.mark.parametrize("check_name", ["04", "05", "09"])
def test_second_page_changes_verdict(client, check_name):
    import importlib
    from sraverify.core.enums import Status
    from sraverify.core.scan_context import ScanContext

    check_cls = getattr(importlib.import_module(f"sraverify.services.config.checks.sra_config_{check_name}"), f"SRA_CONFIG_{check_name}")
    ctx = ScanContext(boto3.Session(region_name="us-east-1"), regions=["us-east-1"])
    ctx.get_account_info = Mock(return_value={"account_id": "111122223333", "account_name": "example"})
    check = check_cls()
    check._ctx = ctx
    check._clients = {"us-east-1": client}
    org = {"ConfigurationAggregatorName": "org", "OrganizationAggregationSource": {"RoleArn": "arn:aws:iam::111122223333:role/example", "AllAwsRegions": True}}
    with Stubber(client.client) as stub:
        stub.add_response("describe_configuration_aggregators", {"ConfigurationAggregators": [{"ConfigurationAggregatorName": "other"}], "NextToken": "next"}, {})
        stub.add_response("describe_configuration_aggregators", {"ConfigurationAggregators": [org]}, {"NextToken": "next"})
        if check_name == "09":
            stub.add_response("describe_configuration_aggregator_sources_status", {"AggregatedSourceStatusList": [{"SourceId": "111122223333", "LastUpdateStatus": "SUCCEEDED"}], "NextToken": "next"}, {"ConfigurationAggregatorName": "org"})
            stub.add_response("describe_configuration_aggregator_sources_status", {"AggregatedSourceStatusList": [{"SourceId": "111122223333", "LastUpdateStatus": "FAILED"}]}, {"ConfigurationAggregatorName": "org", "NextToken": "next"})
        rows = list(check.execute())
        assert len(rows) == 1
        assert rows[0].status == (Status.FAIL if check_name == "09" else Status.PASS)
        if check_name == "09":
            assert "FAILED" in rows[0].actual_value
        stub.assert_no_pending_responses()
