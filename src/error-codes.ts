import { defineErrorCodes } from "better-auth";

/** Error codes the plugin answers with. Also on `$ERROR_CODES` for the client. */
export const DBSC_ERROR_CODES = defineErrorCodes({
  DBSC_DISABLED: "DBSC is turned off",
  DBSC_SESSION_REQUIRED: "DBSC registration needs a signed-in session",
  DBSC_PROOF_REQUIRED: "DBSC registration needs a `Secure-Session-Response` header",
  DBSC_INVALID_CHALLENGE: "The DBSC challenge is missing, expired, or for another session",
  DBSC_INVALID_PROOF: "The DBSC proof is invalid",
  DBSC_BOUND_TO_OTHER_KEY: "This session is bound to another device key",
  DBSC_SESSION_ID_REQUIRED: "A DBSC refresh needs a `Sec-Secure-Session-Id` header",
  DBSC_CHALLENGE_REQUIRED: "Sign the new DBSC challenge and retry",
  DBSC_CREDENTIAL_REQUIRED:
    "This request carries a device-bound session without its device credential",
  DBSC_FRESH_PROOF_REQUIRED: "Confirm this device and try again",
  DBSC_BINDING_REQUIRED: "This action needs a device-bound session",
});
