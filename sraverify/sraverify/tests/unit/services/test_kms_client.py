from unittest.mock import MagicMock

import boto3
from botocore.stub import Stubber

from sraverify.services.kms.client import KMSClient


def test_list_keys_fetches_all_pages():
    client = boto3.client("kms", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    ctx = MagicMock()
    ctx.get_client.return_value = client
    wrapper = KMSClient("us-east-1", ctx)
    with Stubber(client) as stub:
        stub.add_response("list_keys", {"Keys": [{"KeyId": "a"}], "Truncated": True, "NextMarker": "next"}, {})
        stub.add_response("list_keys", {"Keys": [{"KeyId": "b"}], "Truncated": False}, {"Marker": "next"})
        assert wrapper.list_keys()["Keys"] == [{"KeyId": "a"}, {"KeyId": "b"}]


def test_list_keys_reports_later_page_failure():
    client = boto3.client("kms", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    ctx = MagicMock()
    ctx.get_client.return_value = client
    wrapper = KMSClient("us-east-1", ctx)
    with Stubber(client) as stub:
        stub.add_response("list_keys", {"Keys": [{"KeyId": "a"}], "Truncated": True, "NextMarker": "next"}, {})
        stub.add_client_error("list_keys", "AccessDeniedException", "denied", expected_params={"Marker": "next"})
        assert wrapper.list_keys()["Error"]["Code"] == "AccessDeniedException"
