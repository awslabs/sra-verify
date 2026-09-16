"""
SRA-SECURITYHUB-05: Security Hub check.
"""
from collections.abc import Iterable

from sraverify.core.enums import AccountType, Severity
from sraverify.core.finding import Finding
from sraverify.core.metadata import CheckMeta, Remediation
from sraverify.services.securityhub.base import SecurityHubCheck


class SRA_SECURITYHUB_05(SecurityHubCheck):
    """Check if Security Hub has integrations with findings generating products."""

    meta = CheckMeta(
        check_id="SRA-SECURITYHUB-05",
        title="Security Hub integration with findings generating products",
        description=(
            "This check verifies whether Security Hub has expected integration with AWS services "
            "and third party products to ingest security findings."
        ),
        check_logic=(
            "Check looks in audit account to evaluate see what types of findings are being ingested. "
            "PASS if there are any products listed."
        ),
        severity=Severity.MEDIUM,
        account_type=AccountType.AUDIT,
        service="SecurityHub",
        resource_type="AWS::SecurityHub::Hub",
        remediation=Remediation(
            text=(
                "Enable Security Hub product integrations for the findings-generating "
                "services in use, such as GuardDuty, Inspector, and Macie, in every "
                "enabled Region."
            ),
            cli=(
                "aws securityhub enable-import-findings-for-product "
                "--product-arn <product-arn> --region <region>"
            ),
            console=(
                "Security Hub console in the audit account, Integrations, select the "
                "product, Accept findings."
            ),
        ),
    )

    def execute(self) -> Iterable[Finding]:
        """
        Execute the check.

        Yields:
            One Finding per Region.
        """
        # Check each region separately
        for region in self.regions:
            # Get enabled products for import in this specific region
            products_response = self.get_enabled_products_for_import(region)

            resource_id = f"securityhub:integrations/{self.account_id}"

            if "Error" in products_response:
                error = products_response["Error"]
                if self.is_not_configured(error):
                    yield self.failed(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub enabled with product integrations",
                        actual_value=f"Security Hub is not enabled in region {region}",
                        remediation=(
                            f"Enable Security Hub in region {region} first. "
                            "Use the AWS CLI command: "
                            f"aws securityhub enable-security-hub --region {region}, "
                            "then configure product integrations."
                        ),
                    )
                else:
                    yield self.error(
                        region=region,
                        resource_id=resource_id,
                        checked_value="Security Hub enabled with product integrations",
                        actual_value=(
                            f"{error['Operation']} failed: {error['Code']}: "
                            f"{error['Message']}"
                        ),
                        remediation=self._remediation_for(error),
                    )
                continue

            enabled_products = products_response.get('ProductSubscriptions', [])

            if not enabled_products:
                # Security Hub is enabled but no products configured
                yield self.failed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="List of products that are enabled in Security Hub",
                    actual_value=f"Security Hub has no enabled security integrations in region {region}",
                    remediation=(
                        "Enable integrations with security findings generating products. In the Security Hub console, "
                        "navigate to Integrations and enable relevant AWS services like GuardDuty, Inspector, Macie, etc. "
                        "Alternatively, use the AWS CLI command: "
                        f"aws securityhub enable-import-findings-for-product --product-arn [PRODUCT_ARN] --region {region}"
                    ),
                )
            else:
                # Security Hub is enabled with products
                product_names = []
                for product_arn in enabled_products:
                    # Extract the product name from the ARN
                    if '/product-subscription/' in product_arn:
                        product_name = product_arn.split('/product-subscription/')[1]
                        product_names.append(product_name)
                    else:
                        product_names.append(product_arn)

                products_list = ', '.join(product_names) if product_names else "None"

                yield self.passed(
                    region=region,
                    resource_id=resource_id,
                    checked_value="List of products that are enabled in Security Hub",
                    actual_value=f"Security Hub has enabled security integrations in region {region}: {products_list}",
                )
