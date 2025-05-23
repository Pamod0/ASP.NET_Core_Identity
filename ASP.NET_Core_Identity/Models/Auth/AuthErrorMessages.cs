﻿namespace ASP.NET_Core_Identity.Models.Auth
{
    public static class AuthErrorMessages
    {
        public const string RegistrationFailed = "Registration failed. Please try again.";

        public const string InvalidLoginAttempt = "Invalid login attempt.";
        public const string AccountLockedOut = "Account temporarily locked. Please try again later or reset your password.";
        public const string EmailNotConfirmed = "Please confirm your email address before logging in.";
        public const string TwoFactorRequired = "Two-factor authentication required.";
    }

}
