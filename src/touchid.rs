//! Touch ID approval for signers created with `--require-touch-id`.
//!
//! The check runs in this binary before each signature (LocalAuthentication),
//! and the key's keychain item only trusts this signed binary, so another
//! program can neither read the key nor sign without the user's approval.

use crate::error::SignerError;

fn unavailable() -> SignerError {
    let message = if cfg!(target_os = "macos") {
        "Touch ID is not available on this Mac. It needs a Mac with Touch ID, a logged-in user and an enrolled fingerprint."
    } else {
        "Touch ID is only available on macOS."
    };
    SignerError::new("touch_id_unavailable", message)
}

#[cfg(target_os = "macos")]
mod platform {
    use std::sync::mpsc;
    use std::time::Duration;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    use super::unavailable;
    use crate::error::{Result, SignerError};

    /// Biometrics must be set up to create a Touch ID signer.
    pub fn available() -> Result<()> {
        // SAFETY: LAContext is created and used on this thread only.
        let context = unsafe { LAContext::new() };
        unsafe {
            context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
        }
        .map_err(|_| unavailable())
    }

    /// Asks for Touch ID, falling back to the login password when the sensor
    /// can't be used (for example a closed laptop lid).
    pub fn approve(reason: &str) -> Result<()> {
        // SAFETY: as above; the reply block only sends on a channel.
        let context = unsafe { LAContext::new() };
        let (sender, receiver) = mpsc::channel();
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            let _ = sender.send(success.as_bool());
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &NSString::from_str(reason),
                &reply,
            );
        }
        match receiver.recv_timeout(Duration::from_secs(120)) {
            Ok(true) => Ok(()),
            Ok(false) => Err(SignerError::new(
                "touch_id_denied",
                "The signature was not approved with Touch ID.",
            )),
            Err(_) => {
                unsafe { context.invalidate() };
                Err(SignerError::new(
                    "touch_id_timeout",
                    "Touch ID approval timed out after two minutes.",
                ))
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use super::unavailable;
    use crate::error::Result;

    pub fn available() -> Result<()> {
        Err(unavailable())
    }

    pub fn approve(_reason: &str) -> Result<()> {
        Err(unavailable())
    }
}

pub use platform::{approve, available};
