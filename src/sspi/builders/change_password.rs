use std::cell::RefCell;
use std::ops::DerefMut;

use crate::{Error, ErrorKind, Result, SecurityBuffer};

pub struct ChangePassword<'a> {
    pub domain_name: String,
    pub account_name: String,
    pub old_password: String,
    pub new_password: String,
    pub impersonating: bool,
    pub output: &'a mut [SecurityBuffer],
}

#[derive(Default)]
struct ChangePasswordBuilderInner<'a> {
    domain_name: Option<String>,
    account_name: Option<String>,
    old_password: Option<String>,
    new_password: Option<String>,
    impersonating: bool,
    output: Option<&'a mut [SecurityBuffer]>,
}

pub struct ChangePasswordBuilder<'a> {
    inner: RefCell<ChangePasswordBuilderInner<'a>>,
}

impl<'a> ChangePasswordBuilder<'a> {
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(ChangePasswordBuilderInner::default()),
        }
    }

    /// Required
    pub fn with_domain_name(&self, domain_name: String) -> &Self {
        self.inner.borrow_mut().domain_name = Some(domain_name);
        self
    }

    /// Required
    pub fn with_account_name(&self, account_name: String) -> &Self {
        self.inner.borrow_mut().account_name = Some(account_name);
        self
    }

    /// Required
    pub fn with_old_password(&self, old_password: String) -> &Self {
        self.inner.borrow_mut().old_password = Some(old_password);
        self
    }

    /// Required
    pub fn with_new_password(&self, new_password: String) -> &Self {
        self.inner.borrow_mut().new_password = Some(new_password);
        self
    }

    /// Optional(default to false if not set)
    pub fn with_impersonating(&self, impersonating: bool) -> &Self {
        self.inner.borrow_mut().impersonating = impersonating;
        self
    }

    /// Required
    pub fn with_output(&self, output: &'a mut [SecurityBuffer]) -> &Self {
        self.inner.borrow_mut().output = Some(output);
        self
    }

    pub fn build(&self) -> Result<ChangePassword<'a>> {
        let mut inner = self.inner.borrow_mut();

        let ChangePasswordBuilderInner {
            domain_name,
            account_name,
            old_password,
            new_password,
            impersonating,
            output,
        } = inner.deref_mut();

        Ok(ChangePassword {
            domain_name: domain_name
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing domain_name parameter".into()))?,
            account_name: account_name
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing account_name parameter".into()))?,
            old_password: old_password
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing old_password parameter".into()))?,
            new_password: new_password
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing new_password parameter".into()))?,
            impersonating: *impersonating,
            output: output
                .take()
                .ok_or_else(|| Error::new(ErrorKind::InvalidParameter, "Missing output parameter".into()))?,
        })
    }
}

impl<'a> Default for ChangePasswordBuilder<'a> {
    fn default() -> Self {
        Self::new()
    }
}
