"""Kerberos password validation tests."""

from django.urls import reverse

from authentik.core.tests.utils import create_test_flow, create_test_user
from authentik.flows.markers import StageMarker
from authentik.flows.models import FlowDesignation, FlowStageBinding
from authentik.flows.planner import PLAN_CONTEXT_PENDING_USER, FlowPlan
from authentik.flows.tests import FlowTestCase
from authentik.flows.views.executor import SESSION_KEY_PLAN
from authentik.lib.generators import generate_id
from authentik.providers.kerberos.models import KerberosProvider, KerberosUserKeys
from authentik.stages.password import BACKEND_INBUILT
from authentik.stages.password.models import PasswordStage


class KerberosPasswordStageTests(FlowTestCase):
    """Test Kerberos key backfill from password stages."""

    def setUp(self):
        super().setUp()
        self.user = create_test_user()
        self.provider = KerberosProvider.objects.create(
            name=generate_id(),
            realm_name=generate_id(),
        )
        self.flow = create_test_flow(FlowDesignation.AUTHENTICATION)
        self.stage = PasswordStage.objects.create(
            name=generate_id(),
            backends=[BACKEND_INBUILT],
        )
        self.binding = FlowStageBinding.objects.create(target=self.flow, stage=self.stage, order=2)

    def start_flow(self):
        plan = FlowPlan(flow_pk=self.flow.pk.hex, bindings=[self.binding], markers=[StageMarker()])
        plan.context[PLAN_CONTEXT_PENDING_USER] = self.user
        session = self.client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()

    def test_successful_password_validation_backfills_keys(self):
        """A successful password stage creates missing Kerberos keys."""
        self.start_flow()

        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            {"password": self.user.username},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            KerberosUserKeys.objects.filter(user=self.user, provider=self.provider).exists()
        )

    def test_failed_password_validation_does_not_backfill_keys(self):
        """A failed password stage does not create Kerberos keys."""
        self.start_flow()

        response = self.client.post(
            reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug}),
            {"password": f"{self.user.username}-invalid"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(
            KerberosUserKeys.objects.filter(user=self.user, provider=self.provider).exists()
        )
