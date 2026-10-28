-- Tanya transcript access level per team member (agreed with Jazmin and Jake).
-- 'all' = every meeting; 'standard' = client/talent meetings + internal meetings attended.
ALTER TABLE public.accounts
  ADD COLUMN IF NOT EXISTS transcript_access text NOT NULL DEFAULT 'standard'
  CHECK (transcript_access IN ('all', 'standard'));

select email, "displayName", "slackId", team, transcript_access
from public.accounts
order by email;
