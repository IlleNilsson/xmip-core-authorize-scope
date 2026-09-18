#![forbid(unsafe_code)]

//! Scope authorization — a technology of `xmip-core-authorize`.
//!
//! One policy: the scopes a token carries against the scope an action needs.
//! OAuth 2.0 (RFC 6749 section 3.3) lets an authorization server say what a
//! token is for as a space-separated list of scope names, and the verifier
//! that accepted the token — `authenticate/oauth2` by introspection,
//! `authenticate/jwt` from the `scope` claim — records that list on the
//! identity's evidence under the name [`EVIDENCE`]. This policy reads it
//! there and nowhere else: it never sees the token, and a token that was not
//! verified has no evidence to read.
//!
//! A [`Requirement`] says what one action on one artifact needs. The policy
//! has an opinion only where a requirement applies; an attempt nothing
//! requires a scope for is left to the next policy — `None` — because a
//! scope rule for Billing says nothing about a folder drop with no token at
//! all. Where requirements apply, every one of them must be met, and the
//! denial names the scope that was missing and what the token carried, so
//! the operator reading it can tell a wrong token from a wrong rule.
//!
//! Transport layer (ADR-0050 section 5): the identity judged is the one
//! accountable for the transmission, `IdentityFacts::accountable()`, because
//! that is the connection the token arrived on.

pub mod requirement;

use authorize::{Attempt, Authorizer, Decision};
use context::{AuthenticatedIdentity, IdentityFacts};
pub use requirement::Requirement;
use xcore::Layer;

/// The manifest leaf, and what a denial says it was denied by.
pub const NAME: &str = "scope";

/// The evidence name the verifier records a token's scopes under: the
/// space-separated list as the authorization server stated it, and one
/// entry per statement where there were several.
pub const EVIDENCE: &str = "scope";

/// The requirements, all of which must be met where they apply.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Scope {
    requirements: Vec<Requirement>,
}

impl Scope {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn requiring(mut self, requirement: Requirement) -> Self {
        self.requirements.push(requirement);
        self
    }

    #[must_use]
    pub fn requirements(&self) -> &[Requirement] {
        &self.requirements
    }
}

/// The scopes an identity carries, read from its evidence.
#[must_use]
pub fn carried(identity: &AuthenticatedIdentity) -> Vec<&str> {
    identity
        .evidence
        .iter()
        .filter(|(name, _)| name == EVIDENCE)
        .flat_map(|(_, value)| value.split_whitespace())
        .collect()
}

impl Authorizer for Scope {
    fn name(&self) -> &str {
        NAME
    }

    fn layer(&self) -> Layer {
        Layer::Transport
    }

    fn decide(&self, identity: &IdentityFacts, attempt: &Attempt) -> Option<Decision> {
        let applicable: Vec<&Requirement> = self
            .requirements
            .iter()
            .filter(|requirement| requirement.applies(attempt.action, &attempt.artifact))
            .collect();

        if applicable.is_empty() {
            return None;
        }

        let scopes = carried(identity.accountable());
        let missing = applicable
            .iter()
            .find(|requirement| !requirement.met_by(scopes.iter().copied()));

        let Some(requirement) = missing else {
            return Some(Decision::Allowed);
        };

        let has = if scopes.is_empty() {
            "carries no scope".to_string()
        } else {
            format!("carries {}", scopes.join(" "))
        };

        Some(Decision::denied(
            NAME,
            format!(
                "{} on '{}' needs scope '{}', and the token {has}",
                attempt.action, attempt.artifact, requirement.scope
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorize::Action;
    use context::{Alignment, Verified};
    use xcore::{Established, mechanism};

    fn bearer(scopes: &[&str]) -> IdentityFacts {
        let mut identity = AuthenticatedIdentity::new(
            mechanism::oauth2(),
            "client-billing",
            Established::Passed,
            Verified::Proven,
        );

        for statement in scopes {
            identity = identity.with_evidence(EVIDENCE, *statement);
        }

        IdentityFacts::evaluate(Alignment::None, identity, None)
    }

    fn billing() -> Scope {
        Scope::new()
            .requiring(Requirement::new("Billing", "billing:*").for_action(Action::Send))
            .requiring(Requirement::new("Billing", "partner").for_action(Action::Send))
    }

    #[test]
    fn a_token_carrying_every_required_scope_is_allowed() {
        let decision = billing().decide(
            &bearer(&["partner billing:write"]),
            &Attempt::new(Action::Send, "Billing"),
        );

        assert_eq!(decision, Some(Decision::Allowed));
    }

    #[test]
    fn a_missing_scope_is_denied_by_scope_naming_it_and_what_the_token_carries() {
        let decision = billing().decide(
            &bearer(&["partner", "orders:read"]),
            &Attempt::new(Action::Send, "Billing"),
        );

        assert_eq!(
            decision.map(|decision| decision.to_string()),
            Some(
                "denied by scope: send on 'Billing' needs scope 'billing:*', and the token \
                 carries partner orders:read"
                    .to_string()
            )
        );
    }

    #[test]
    fn an_attempt_no_requirement_covers_is_left_to_the_next_policy() {
        // The requirements are about sending through Billing. Receiving into
        // it, and anything on Payroll, is not this policy's business.
        let policy = billing();
        let token = bearer(&[]);

        assert_eq!(
            policy.decide(&token, &Attempt::new(Action::Receive, "Billing")),
            None
        );
        assert_eq!(
            policy.decide(&token, &Attempt::new(Action::Send, "Payroll")),
            None
        );
    }

    #[test]
    fn an_identity_with_no_scope_evidence_is_denied_saying_it_carries_none() {
        let decision = billing().decide(&bearer(&[]), &Attempt::new(Action::Send, "Billing"));

        assert_eq!(
            decision,
            Some(Decision::denied(
                NAME,
                "send on 'Billing' needs scope 'billing:*', and the token carries no scope"
            ))
        );
    }

    #[test]
    fn scopes_are_read_from_every_scope_evidence_entry_split_on_whitespace() {
        let facts = bearer(&["a b", "c"]);

        assert_eq!(carried(facts.accountable()), vec!["a", "b", "c"]);
        assert_eq!(Scope::new().name(), "scope");
        assert_eq!(Scope::new().layer(), Layer::Transport);
    }
}
