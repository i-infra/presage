use std::borrow::Cow;

use libsignal_service::prelude::MessageSenderError;
use libsignal_service::protocol::UsernameError;
use libsignal_service::websocket::registration::RegistrationSessionMetadataResponse;
use libsignal_service::{models::ParseContactError, protocol::SignalProtocolError};

use crate::store::{StoreError, ThreadError};

/// The error type of Signal manager
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error<S: std::error::Error> {
    #[error("captcha from https://signalcaptchas.org/registration/generate.html required")]
    CaptchaRequired,
    #[error("input/output error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("error decoding base64 data: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("wrong slice size: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("phone number parsing error: {0}")]
    PhoneNumberError(#[from] libsignal_service::prelude::phonenumber::ParseError),
    #[error("UUID decoding error: {0}")]
    UuidError(#[from] libsignal_service::prelude::UuidError),
    #[error("Invalid thread: {0}")]
    InvalidThread(#[from] ThreadError),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] SignalProtocolError),
    #[error("libsignal-service error: {0}")]
    ServiceError(#[from] libsignal_service::prelude::ServiceError),
    #[error("libsignal-service error: {0}")]
    ProfileManagerError(#[from] libsignal_service::ProfileManagerError),
    #[error("libsignal-service sending error: {0}")]
    MessageSenderError(Box<MessageSenderError>),
    #[error("this client is already registered with Signal")]
    AlreadyRegisteredError,
    #[error("this client is not yet registered, please register or link as a secondary device")]
    NotYetRegisteredError,
    #[error("failed to provision device: {0}")]
    ProvisioningError(#[from] libsignal_service::provisioning::ProvisioningError),
    #[error("no provisioning message received")]
    NoProvisioningMessageReceived,
    #[error("qr code error")]
    LinkingError,
    #[error("please relink your client")]
    RelinkNecessary,
    #[error("missing key {0} in config DB")]
    MissingKeyError(Cow<'static, str>),
    #[error("message pipe not started, you need to start receiving messages before you can send anything back")]
    MessagePipeNotStarted,
    #[error("receiving pipe was interrupted")]
    MessagePipeInterruptedError,
    #[error("failed to parse contact information: {0}")]
    ParseContactError(#[from] ParseContactError),
    #[error("failed to decrypt attachment: {0}")]
    AttachmentCipherError(#[from] libsignal_service::attachment_cipher::AttachmentCipherError),
    #[error("group encryption/decryption failed: {0}")]
    GroupDecodingError(#[from] libsignal_service::groups_v2::GroupDecodingError),
    #[error("unknown group")]
    UnknownGroup,
    #[error("unknown recipient")]
    UnknownRecipient,
    /// Refused to leave a group that would be left without an administrator.
    ///
    /// Promote another member first, or pass `force` to leave anyway.
    #[error("refusing to leave group as its last admin")]
    LastGroupAdmin,
    /// The groups server refused to let us read the group.
    ///
    /// Group reads authenticate with a membership proof, so this means we are
    /// not a member — typically because we already left.
    #[error("not a member of this group")]
    NotAGroupMember,
    #[error("invalid group invite link: {0}")]
    InvalidInviteLink(#[from] libsignal_service::groups_v2::InviteLinkError),
    /// The link's group refused it: links are disabled or the password was
    /// rotated since the link was shared.
    #[error("group invite link is no longer valid")]
    InviteLinkRevoked,
    #[error("timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("store error: {0}")]
    Store(S),
    #[error("push challenge required (not implemented)")]
    PushChallengeRequired,
    #[error("Not allowed to request verification code, reason unknown: {0:?}")]
    RequestingCodeForbidden(RegistrationSessionMetadataResponse),
    #[error("attachment sha256 checksum did not match")]
    UnexpectedAttachmentChecksum,
    #[error("Unverified registration session (i.e. wrong verification code)")]
    UnverifiedRegistrationSession,
    #[error("profile cipher error")]
    ProfileCipherError(#[from] libsignal_service::profile_cipher::ProfileCipherError),
    #[error("An operation was requested that requires the registration to be primary, but it was only secondary")]
    NotPrimaryDevice,
    #[error("Failed to get initial messages after uploading pre-keys")]
    UpdatePreKeyFailure,
    #[error("invalid device ID (out of bounds)")]
    InvalidDeviceId,
    #[error("invalid Signal username: {0}")]
    InvalidUsername(#[from] UsernameError),
}

impl<S: std::error::Error> From<MessageSenderError> for Error<S> {
    fn from(v: MessageSenderError) -> Self {
        Self::MessageSenderError(Box::new(v))
    }
}

impl<S: StoreError> From<S> for Error<S> {
    fn from(e: S) -> Self {
        Self::Store(e)
    }
}
