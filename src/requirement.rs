//! A requirement: the scope an action on an artifact needs.

use authorize::Action;

/// The scope one action on one artifact, or every artifact under a prefix,
/// needs a token to carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Requirement {
    /// The point this requirement is for, or every point when `None`.
    pub action: Option<Action>,
    /// The artifact's name, or every name under a prefix when it ends in `*`.
    pub artifact: String,
    /// The scope the token must carry: a name, or every name under a prefix
    /// when it ends in `*` — `billing:*` is met by `billing:read`.
    pub scope: String,
}

impl Requirement {
    /// Every action on the artifact needs the scope.
    #[must_use]
    pub fn new(artifact: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            action: None,
            artifact: artifact.into(),
            scope: scope.into(),
        }
    }

    /// Only this action needs it.
    #[must_use]
    pub const fn for_action(mut self, action: Action) -> Self {
        self.action = Some(action);
        self
    }

    /// Whether this requirement is about this action on this artifact.
    #[must_use]
    pub fn applies(&self, action: Action, artifact: &str) -> bool {
        self.action.is_none_or(|own| own == action) && prefix_matches(&self.artifact, artifact)
    }

    /// Whether one of the scopes a token carries meets this requirement.
    #[must_use]
    pub fn met_by<'a>(&self, carried: impl IntoIterator<Item = &'a str>) -> bool {
        carried
            .into_iter()
            .any(|scope| prefix_matches(&self.scope, scope))
    }
}

/// A name, or every name under a prefix when the pattern ends in `*`.
fn prefix_matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_requirement_without_an_action_applies_to_every_point() {
        let any = Requirement::new("Billing", "billing");
        let send = Requirement::new("Billing", "billing").for_action(Action::Send);

        assert!(any.applies(Action::Receive, "Billing"));
        assert!(any.applies(Action::Send, "Billing"));
        assert!(send.applies(Action::Send, "Billing"));
        assert!(!send.applies(Action::Receive, "Billing"));
        assert!(!any.applies(Action::Send, "Payroll"));
    }

    #[test]
    fn a_scope_prefix_is_met_by_any_scope_under_it() {
        let requirement = Requirement::new("Billing", "billing:*");

        assert!(requirement.met_by(["orders:read", "billing:read"]));
        assert!(!requirement.met_by(["orders:read"]));
        assert!(!requirement.met_by([]));
    }
}
