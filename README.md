# Insider Threat & Data Exfiltration Detection with KQL

Detection rules written in **KQL (Kusto Query Language)**, the query language used by **Microsoft Sentinel** and Defender Advanced Hunting, to find data theft in one month of security logs for **ShopNest**, a fictional e-commerce company.

> All companies, people and data in this project are fictional.

## The scenario
Management suspects customer data is leaving the company. I had one month of logs (October 2026) for 16 employees and had to find who, if anyone, was taking data, while separating real threats from innocent activity that only looked suspicious.

## Dataset (`data/`)
| Table | Rows | Similar to (Microsoft) |
|---|---|---|
| `SigninLogs` | 455 | Entra ID `SigninLogs` |
| `FileActivity` | 5,987 | `OfficeActivity` (SharePoint) |
| `EmailEvents` | 1,690 | Defender `EmailEvents` |
| `HR_Employees` | 16 | HR data used by Insider Risk Management |

Loaded into a free Azure Data Explorer cluster.

## Detection rules (`queries/`)
| File | What it detects |
|---|---|
| `00_baseline.kql` | Normal download volume per user |
| `01_mass_download.kql` | Daily downloads 5x above the user's own median (min. 15) |
| `02_after_hours.kql` | Confidential downloads before 8 am or after 8 pm, India time |
| `03_foreign_signin.kql` | Sign-ins from outside India, including failed attempts |
| `04_leaver_risk.kql` | Downloads before vs after resignation (HR join) |
| `05_personal_email.kql` | Confidential attachments sent to personal email domains |
| `06_risk_score.kql` | All rules combined into one ranked risk score |

## Results
| User | Risk score | Verdict |
|---|---|---|
| Anita | 90 | **Malicious insider:** after resigning, downloaded customer files at night and emailed them to personal Gmail |
| Priya | 60 | **Compromised account:** 6 failed logins from Brazil on an unknown device, then 42 customer files downloaded at 2 am IST |
| Rahul | 20 | Benign: month-end finance close |
| Vikram | 20 | Benign: business trip on his own laptop |

The rules found both real threats and kept the innocent anomalies at the bottom of the list. Response steps are in [`TRIAGE_PLAYBOOK.md`](TRIAGE_PLAYBOOK.md).

## What I learned
- **Baselines beat fixed thresholds:** compare each user to their own normal day.
- **Context decides:** a foreign login or a download spike is a signal, not proof.
- **Time zones matter:** logs are in UTC; after-hours logic only works in local time.
- **Correlation:** a user triggering several rules is far more likely to be a real threat.

## Skills
KQL (`where`, `summarize`, `join`, `let`, `union`, `countif`, `percentile`, `make_set`, time conversion) · insider threat detection · data exfiltration routes · baselining · false-positive tuning · risk scoring · incident triage

**Author:** Priti More · [LinkedIn](https://www.linkedin.com/in/er-priti-more-2209bb27b/) · [GitHub](https://github.com/pritimore-security)
