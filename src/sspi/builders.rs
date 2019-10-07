mod accept_sec_context;
mod acq_cred_handle;
mod init_sec_context;

pub use self::{
    accept_sec_context::{
        AcceptSecurityContext, AcceptSecurityContextResult, EmptyAcceptSecurityContext,
        FilledAcceptSecurityContext,
    },
    acq_cred_handle::{
        AcquireCredentialsHandle, AcquireCredentialsHandleResult, EmptyAcquireCredentialsHandle,
        FilledAcquireCredentialsHandle, WithCredentialUse, WithoutCredentialUse,
    },
    init_sec_context::{
        EmptyInitializeSecurityContext, FilledInitializeSecurityContext, InitializeSecurityContext,
        InitializeSecurityContextResult,
    },
};

use std::fmt;

pub trait ToAssign: fmt::Debug {}
pub trait Assigned: ToAssign {}
pub trait NotAssigned: ToAssign {}

#[derive(Debug)]
pub struct WithCredentialsHandle;
impl ToAssign for WithCredentialsHandle {}
impl Assigned for WithCredentialsHandle {}

#[derive(Debug)]
pub struct WithoutCredentialsHandle;
impl ToAssign for WithoutCredentialsHandle {}
impl NotAssigned for WithoutCredentialsHandle {}

#[derive(Debug)]
pub struct WithContextRequirements;
impl ToAssign for WithContextRequirements {}
impl Assigned for WithContextRequirements {}

#[derive(Debug)]
pub struct WithoutContextRequirements;
impl ToAssign for WithoutContextRequirements {}
impl NotAssigned for WithoutContextRequirements {}

#[derive(Debug)]
pub struct WithTargetDataRepresentation;
impl ToAssign for WithTargetDataRepresentation {}
impl Assigned for WithTargetDataRepresentation {}

#[derive(Debug)]
pub struct WithoutTargetDataRepresentation;
impl ToAssign for WithoutTargetDataRepresentation {}
impl NotAssigned for WithoutTargetDataRepresentation {}

#[derive(Debug)]
pub struct WithOutput;
impl ToAssign for WithOutput {}
impl Assigned for WithOutput {}

#[derive(Debug)]
pub struct WithoutOutput;
impl ToAssign for WithoutOutput {}
impl NotAssigned for WithoutOutput {}
