"""Contract tests executing PIIStripperContractSuite against PIIVault."""

from blockstate.ports.security import PIIStripper
from blockstate.security.vault import PIIVault
from blockstate.testing.contracts import PIIStripperContractSuite


class TestPIIVaultStripperContract(PIIStripperContractSuite):
    """Execute 100% of PIIStripperContractSuite assertions against PIIVault."""

    __test__ = True

    def create_stripper(self) -> PIIStripper:
        """Create a fresh PIIVault instance under test."""
        return PIIVault()
