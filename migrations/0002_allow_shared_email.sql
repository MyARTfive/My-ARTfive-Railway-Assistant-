-- Allow the same email address to be used by different account roles.
-- Owner login explicitly prioritizes the Owner account when an email is shared.
DROP INDEX IF EXISTS idx_users_email_unique;
