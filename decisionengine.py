# +-----------------------------------------------------------+
# | decisionengine.py                                         |
# +-----------------------------------------------------------+
# | Purpose:                                                  |
# |  - Translate recon results into a test plan               |
# |  - Choose relevant tests and prioritize execution         |
# |                                                           |
# | Responsibilities:                                         |
# |  - Service -> applicable test mapping                     |
# |  - Compatibility checks (skip irrelevant modules)         |
# |  - Prioritization/risk ordering (optional)                |
# |                                                           |
# | Key Data Models:                                          |
# |  + TestPlan                                                |
# |     - service: Service                                    |
# |     - tests: list[TestModule]                             |
# |                                                           |
# |  + RiskScore (optional)                                   |
# |     - severity: str                                       |
# |     - confidence: float                                   |
# |                                                           |
# | Key Components:                                           |
# |  + DecisionEngine                                         |
# |     + build_plan(services: list[Service]) -> list[TestPlan] |
# |     + prioritize(plans: list[TestPlan]) -> list[TestPlan] |
# |                                                           |
# | Inputs:                                                   |
# |  - list[Service] from reconnaissance                       |
# |                                                           |
# | Outputs:                                                  |
# |  - list[TestPlan] (what tests to run on what service)     |
# +-----------------------------------------------------------+



# decisionengine.py

from typing import List


# ---------------------------
# Data Models
# ---------------------------

class Service:
    def __init__(self, name: str, port: int, protocol: str):
        self.name = name
        self.port = port
        self.protocol = protocol


class TestModule:
    def __init__(self, name: str):
        self.name = name


class RiskScore:
    def __init__(self, severity: str, confidence: float):
        self.severity = severity
        self.confidence = confidence


class TestPlan:
    def __init__(self, service: Service, tests: List[TestModule]):
        self.service = service
        self.tests = tests


# ---------------------------
# Decision Engine
# ---------------------------

class DecisionEngine:

    def build_plan(self, services: List[Service]) -> List[TestPlan]:
        """
        Map discovered services to applicable test modules.
        """
        plans = []

        for service in services:
            tests = self._map_service_to_tests(service)
            plans.append(TestPlan(service, tests))

        return plans


    def prioritize(self, plans: List[TestPlan]) -> List[TestPlan]:
        """
        Optional prioritization logic.
        """
        # Simple placeholder: return as-is
        return plans


    # -----------------------
    # Internal Helpers
    # -----------------------

    def _map_service_to_tests(self, service: Service) -> List[TestModule]:
        """
        Determine which tests apply to a service.
        """
        tests = []

        # Example placeholder logic
        if service.name.lower() == "http":
            tests.append(TestModule("web_config_check"))

        return tests
