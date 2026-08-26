"""Next action flows, required before a user can log in"""

from typing import Any

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.utils.translation import gettext as _
from structlog.stdlib import get_logger

from authentik.core.middleware import SESSION_KEY_IMPERSONATE_USER
from authentik.core.models import USER_ATTRIBUTE_NEXT_ACTIONS, User
from authentik.events.middleware import audit_ignore
from authentik.events.models import Event, EventAction
from authentik.flows.models import Flow, FlowDesignation, in_memory_stage
from authentik.flows.planner import (
    PLAN_CONTEXT_PENDING_USER,
    PLAN_CONTEXT_REDIRECT,
    FlowPlan,
    FlowPlanner,
)
from authentik.flows.stage import StageView
from authentik.flows.views.executor import SESSION_KEY_PLAN

LOGGER = get_logger()

# Flows that create or end a session cannot run as a next action inside a login
NEXT_ACTION_DISALLOWED_DESIGNATIONS = [
    FlowDesignation.AUTHENTICATION,
    FlowDesignation.INVALIDATION,
]

# Paths a user with pending next actions may still use: completing the actions
# themselves (flow interface and executor, with the APIs flow stages call) and
# logging out.
PENDING_ALLOWED_PATH_PREFIXES = (
    "/if/flow/",
    "/flows/",
    "/api/v3/flows/",
    "/api/v3/stages/",
    "/api/v3/sources/",
    "/api/v3/core/users/me/",
    "/api/v3/root/config/",
    "/static/",
    "/media/",
)


def next_actions_enabled() -> bool:
    """Whether next actions are enforced on this install. Any installed license counts,
    even an expired one, so a lapsed license cannot switch off mandatory actions."""
    from authentik.enterprise.license import LicenseKey
    from authentik.enterprise.models import LicenseUsageStatus

    return LicenseKey.cached_summary().status != LicenseUsageStatus.UNLICENSED


def next_action_slugs(value: Any) -> list[str]:
    """Normalize the next-actions attribute value to a list of slugs, without validation"""
    slugs = value if isinstance(value, list) else [value]
    return [slug for slug in slugs if isinstance(slug, str)]


def resolve_next_actions(value: Any) -> list[Flow]:
    """Resolve the value of the next-actions user attribute (a flow slug or
    a list of flow slugs) to flows. Raises ValueError for entries that don't
    resolve to a usable flow."""
    slugs = value if isinstance(value, list) else [value]
    flows = []
    for slug in slugs:
        if not isinstance(slug, str):
            raise ValueError(f"Invalid next action entry: {slug!r}")
        flow = Flow.objects.filter(slug=slug).first()
        if not flow:
            raise ValueError(f"Next action flow does not exist: {slug}")
        if flow.designation in NEXT_ACTION_DISALLOWED_DESIGNATIONS:
            raise ValueError(f"Flow cannot be used as a next action: {slug}")
        flows.append(flow)
    return flows


class NextActionDoneStageView(StageView):
    """Remove a completed next action flow from the pending user's attributes"""

    def dispatch(self, request: HttpRequest) -> HttpResponse:
        user: User | None = self.executor.plan.context.get(PLAN_CONTEXT_PENDING_USER)
        slug = self.executor.current_stage.flow_slug
        if not user:
            return self.executor.stage_ok()
        value = user.attributes.get(USER_ATTRIBUTE_NEXT_ACTIONS)
        if isinstance(value, list):
            if slug in value:
                value.remove(slug)
            if not value:
                user.attributes.pop(USER_ATTRIBUTE_NEXT_ACTIONS, None)
        elif value == slug:
            user.attributes.pop(USER_ATTRIBUTE_NEXT_ACTIONS, None)
        with audit_ignore():
            user.save(update_fields=["attributes"])
        Event.new(EventAction.NEXT_ACTION_COMPLETED, flow_slug=slug).from_http(
            self.request, user=user
        )
        return self.executor.stage_ok()


def plan_next_actions(request: HttpRequest, flows: list[Flow], context: dict) -> FlowPlan:
    """Plan the given next action flows into a single flow plan, each followed by a
    stage that removes it from the user's attributes. Raises FlowNonApplicableException
    when a flow's policies deny the user."""
    plan = FlowPlan(flow_pk=str(flows[0].pk))
    for flow in flows:
        planner = FlowPlanner(flow)
        planner.use_cache = False
        planner.allow_empty_flows = True
        # The pending user has already passed this flow's authentication requirements
        planner.check_authentication = False
        action_plan = planner.plan(request, context)
        plan.bindings.extend(action_plan.bindings)
        plan.markers.extend(action_plan.markers)
        plan.append_stage(in_memory_stage(NextActionDoneStageView, flow_slug=flow.slug))
    return plan


class PendingNextActionsMiddleware:
    """Block a logged-in user with pending next actions from everything except
    completing those actions and logging out.

    Logins through the User Login stage run the actions before the session is created;
    this middleware covers sessions that exist anyway, such as one created before the
    actions were assigned, and with it a pending user cannot side-step the actions by
    authorizing an application (for example over OAuth2) with their existing session."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.block_pending_user(request)
        return response or self.get_response(request)

    def block_pending_user(self, request: HttpRequest) -> HttpResponse | None:
        """Return a response for a user who must complete next actions first,
        None when the request may proceed."""
        user = request.user
        if not user.is_authenticated:
            return None
        if request.path.startswith(PENDING_ALLOWED_PATH_PREFIXES):
            return None
        # An impersonating administrator is not the user who has to act
        if SESSION_KEY_IMPERSONATE_USER in request.session:
            return None
        value = user.attributes.get(USER_ATTRIBUTE_NEXT_ACTIONS)
        if not value:
            return None
        if not next_actions_enabled():
            return None
        from authentik.flows.exceptions import FlowNonApplicableException

        try:
            flows = resolve_next_actions(value)
        except ValueError as exc:
            # Blocking on a broken attribute would leave no way to repair it, so
            # the request is let through and the problem is logged instead.
            LOGGER.warning("Failed to resolve next actions", user=user.username, error=str(exc))
            return None
        if "text/html" not in request.headers.get("Accept", ""):
            return JsonResponse(
                {"detail": _("Complete the required actions before continuing.")},
                status=403,
            )
        try:
            plan = plan_next_actions(request, flows, {PLAN_CONTEXT_PENDING_USER: user})
        except FlowNonApplicableException:
            LOGGER.warning(
                "Next action flow not applicable to user",
                user=user.username,
            )
            return None
        # Send the user back to where they were once the actions are completed
        plan.context[PLAN_CONTEXT_REDIRECT] = request.get_full_path()
        request.session[SESSION_KEY_PLAN] = plan
        messages.info(
            request,
            _("Your administrator requires you to complete actions before continuing."),
        )
        return redirect("authentik_core:if-flow", flow_slug=flows[0].slug)
