# Triage Playbook: ShopNest Insider Threat Detections

All people and data are fictional.

## Risk score and severity

| Rule | Points | Signal |
|---|---|---|
| Download spike (15+ downloads in a day, 5x the user's median) | 20 | Possible data collection |
| Confidential downloads before 8 am or after 8 pm (IST) | 20 | Activity hidden from view |
| Sign-in from outside India | 20 | Possible stolen credentials or travel |
| Leaver (resigned) | 20 | Higher motive |
| Confidential attachment sent to a personal email domain | 30 | Data has left the company |

**Severity:** 60+ High · 30–59 Medium · below 30 Low

## Results

| User | Score | Rules | Verdict |
|---|---|---|---|
| Anita (Customer Service) | 90 | Spike, Night, Leaver, Personal email | True positive: malicious insider |
| Priya (Marketing) | 60 | Spike, Night, Another country | True positive: compromised account |
| Rahul (Finance) | 20 | Spike | Benign true positive: month-end close |
| Vikram (IT) | 20 | Another country | Benign true positive: business trip |
| Karan (Warehouse) | 0 | (Night activity on non-sensitive files only) | Approved night shift; excluded by design |

## Investigation steps (for every alert)

1. **Read the alert:** rule, user, time (convert to IST), files, volume.
2. **Validate content:** are the files really sensitive (label, file names)?
3. **Gather context:** role, baseline, HR status, device, location, failed sign-ins before.
4. **Classify:** true positive, benign true positive or false positive, plus severity.
5. **Act:** contain and escalate (see below).
6. **Document and tune:** root cause, outcome, rule changes.

## Response actions

### Malicious insider (Anita)
- Escalate to the security lead; notify HR and the line manager.
- Privacy / DPO: assess a personal data breach (GDPR Art. 33: notify the authority within 72 hours if there is risk to people).
- Preserve evidence: file activity logs, emails and attachments.
- Block sending Confidential files to personal domains (DLP policy).
- Add leavers to a higher-risk monitoring group during notice periods.

### Compromised account (Priya)
- Revoke active sessions and reset the password.
- Enforce MFA; block sign-ins from unexpected countries (Conditional Access).
- Contact the user by phone, not email (the mailbox may be compromised).
- Privacy / DPO: assess a personal data breach (customer files were downloaded).
- Check for phishing emails received in the days before.

### Benign activity (Rahul, Vikram)
- Confirm with the manager; close with a written justification.
- Tune: document a month-end exception for Finance; record approved travel.

## Tuning notes
- Use the user's own median as the baseline, plus a minimum volume, to avoid flagging small changes.
- Restrict after-hours logic to sensitive data and keep a documented allow-list for shift workers.
- Target personal email domains rather than all external email; approved partners create noise.
