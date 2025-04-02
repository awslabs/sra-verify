import unittest
from unittest.mock import MagicMock, patch
from sraverify.checks.accessanalyzer.SRA_IAA_1 import SRAIAA1
from botocore.exceptions import ClientError

class TestSRAIAA1(unittest.TestCase):
    def setUp(self):
        self.check = SRAIAA1()
        self.check.session = MagicMock()
        self.region = "us-east-1"
        self.account_id = "123456789012"
        self.resource_id = "test-resource"
        
    def test_execute_analyzer_exists(self):
        # Mock the IAM Access Analyzer client
        mock_client = MagicMock()
        self.check.session.client.return_value = mock_client
        
        # Mock response with an active account analyzer
        mock_client.list_analyzers.return_value = {
            'analyzers': [{
                'arn': f'arn:aws:access-analyzer:{self.region}:{self.account_id}:analyzer/test',
                'status': 'ACTIVE',
                'type': 'ACCOUNT'
            }]
        }
        
        findings = []
        self.check.execute(findings, self.region, self.account_id, self.resource_id)
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['Compliance']['Status'], 'PASSED')
        self.assertEqual(finding['ProductFields']['Status'], 'PASS')
        
    def test_execute_no_analyzer(self):
        # Mock the IAM Access Analyzer client
        mock_client = MagicMock()
        self.check.session.client.return_value = mock_client
        
        # Mock response with no analyzers
        mock_client.list_analyzers.return_value = {'analyzers': []}
        
        findings = []
        self.check.execute(findings, self.region, self.account_id, self.resource_id)
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['Compliance']['Status'], 'FAILED')
        self.assertEqual(finding['ProductFields']['Status'], 'FAIL')
        
    def test_execute_client_error(self):
        # Mock the IAM Access Analyzer client
        mock_client = MagicMock()
        self.check.session.client.return_value = mock_client
        
        # Mock a client error
        mock_client.list_analyzers.side_effect = ClientError(
            {'Error': {'Code': 'TestException', 'Message': 'Test error message'}},
            'ListAnalyzers'
        )
        
        findings = []
        self.check.execute(findings, self.region, self.account_id, self.resource_id)
        
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding['Compliance']['Status'], 'FAILED')
        self.assertEqual(finding['ProductFields']['Status'], 'ERROR')
        
if __name__ == '__main__':
    unittest.main()