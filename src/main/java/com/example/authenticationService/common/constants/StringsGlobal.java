package com.example.authenticationService.common.constants;

public class StringsGlobal {
    private StringsGlobal() {
        // Utility class
    }

    public static final class Auth {
        private Auth() {}

        // Signup
        public static final String SIGNUP_SUCCESS = "auth.signup.success";
        public static final String SIGNUP_VERIF_SUCCESS = "auth.signup.verif.success";
        public static final String SIGNUP_OTP_SENT = "auth.signup.otp.code.sent";
        public static final String SIGNUP_GOOGLE_NO_MAIL="auth.signup.google.no.email";
        public static final String SIGNUP_USERNAME_TAKEN = "auth.signup.username_taken";
        public static final String SIGNUP_EMAIL_TAKEN = "auth.signup.email_taken";
        public static final String SIGNUP_INVALID_REQUEST = "auth.signup.invalid_request";
        public static final String SIGNUP_UNEXPECTED_ERROR = "auth.signup.unexpected_error";
        public static final String SIGNUP_RESEND_CD = "auth.signup.resend.cd.otp";
        public static final String SIGNUP_TOO_MANY_ATT = "auth.signup.too.many.attempts";
        public static final String SIGNUP_ALR_VERIF = "auth.signup.alr.verif";
        public static final String SIGNUP_OTP_FAILED_SEND = "auth.signup.failed.send.otp";
        public static final String SIGNUP_FNAME_REQ="auth.signup.fname.req";
        public static final String SIGNUP_LNAME_REQ="auth.signup.lname.req";
        public static final String SIGNUP_UNAME_REQ="auth.signup.uname.req";
        public static final String SIGNUP_INV_EMAIL="auth.signup.inv.email.frmt";
        public static final String SIGNUP_EMAIL_REQ="auth.signup.email.req";

        // Login
        public static final String LOGIN_SUCCESS = "auth.login.success";
        public static final String LOGIN_USER_NOT_FOUND = "auth.login.user.not.found";
        public static final String UNAME_REQUIRED = "auth.login.username.required";
        public static final String PASS_REQUIRED = "auth.login.password.required";
        public static final String LOGIN_INVALID_CREDENTIALS = "auth.login.invalid.credentials";
        public static final String LOGIN_ACCOUNT_LOCKED = "auth.login.account.locked";
        public static final String LOGIN_ACCOUNT_DISABLED = "auth.login.account.disabled";
        public static final String LOGIN_ACCOUNT_SUSPENDED = "auth.login.account.suspended";
        public static final String LOGIN_ACCOUNT_INACTIVE = "auth.login.account.inactive";
    }

    public static final class UserStatus {
        private UserStatus() {}

        public static final String ACTIVE = "user.status.active";
        public static final String INACTIVE = "user.status.inactive";
        public static final String LOCKED = "user.status.locked";
        public static final String DISABLED = "user.status.disabled";
        public static final String PENDING = "user.status.pending";
        public static final String DELETED = "user.status.deleted";
    }

    public static final class Error {
        private Error() {}

        public static final String UNAUTHORIZED = "error.unauthorized";
        public static final String FORBIDDEN = "error.forbidden";
        public static final String INTERNAL = "error.internal";
        public static final String BAD_REQUEST = "error.bad_request";
        public static final String NOT_FOUND = "error.not_found";
        public static final String TOO_MANY_ATT = "error.too.many.attempts";
        public static final String ERR_INV_CODE = "error.inv.code";
        public static final String EMAIL_NT_FND = "error.email.nt.fnd";
        public static final String INV_INPUT = "error.inv.input";
        public static final String INV_STRING = "error.inv.string";
    }

    public static final class Commons {
        private Commons() {}

        public static final String CODE_ALR_USED = "code.alr.used";
        public static final String NOPEND_VERIF = "nopend.verif";
        public static final String CODE_EXP = "code.exp";
        public static final String LOGGED_OUT = "logged.out.succ";

    }
}
