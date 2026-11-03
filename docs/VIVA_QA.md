# Viva Preparation: AI-Based SOC Log Analyzer

Short, honest answers. Know these in your own words.

## The basics

**1. What does your project do?**
It reads security logs, finds suspicious activity with rules and an anomaly-detection model, scores
each finding, and shows the results in a dashboard where an analyst can investigate and export them.

**2. What is a SOC?**
A Security Operations Center: the team and tools that monitor logs and alerts to detect and respond
to security incidents. This project is a simplified version of that tooling.

**3. Does it attack or scan anything?**
No. It only reads log files that are uploaded to it.

**4. Walk me through the pipeline.**
Upload, parse and normalize, extract features, run rules and the ML model, combine and score,
store alerts in SQLite, show in the dashboard, investigate, export a report. All stored in one
transaction.

## Detection

**5. How does brute-force detection work?**
A sliding time window per source IP counts failed logins. More than 5 within 120 seconds raises an
alert. Overlapping windows merge into one alert. It also checks for a successful login from the same
IP afterwards, which suggests the account may be compromised.

**6. How do you detect a port scan?**
Count distinct destination ports contacted by one IP within a window. More than 15 within 60 seconds.
Repeating the same port many times is not a scan.

**7. Are the thresholds hard-coded?**
No. They are in `config.py`, validated at start, and shown on the Settings page.

**8. Why do some alerts disappear when I raise a threshold?**
Rules are simple. A higher threshold means fewer false positives and more misses. Tuning that trade-off
is part of using any rule-based detector.

**9. What is a false positive? How do analysts handle it?**
An alert on harmless activity (for example a night-shift admin tripping the off-hours rule).
Analysts set the status to False Positive. The rules can also be tuned or disabled.

## Machine learning

**10. Which algorithm and why?**
Isolation Forest. It isolates points with random splits; unusual points need fewer splits. It is
unsupervised, so it works without labelled attack data, which we do not have.

**11. What features does it use?**
Thirteen: time of day (cyclic), failure flag, external IP, sensitive event, per-IP event counts and
bursts, failure ratio, distinct ports and users per IP, distinct IPs per user, and port and
event-type rarity.

**12. What is the accuracy of your model?**
There is none to report. Accuracy needs labelled data, and this project has none. The model is an
anomaly detector, not a classifier. We can say what it flags and why, not how often it is "right".

**13. What does `contamination` do?**
It sets the share of events flagged as anomalies (5% by default). So the number of anomalies follows
this setting. It is not the number of attacks.

**14. When does the ML fail?**
If a file is mostly malicious, attacks look normal to the model. With fewer than 50 events it is
skipped. It can also flag unusual but harmless behaviour.

**15. Why use ML if rules already find the attacks?**
Rules only catch patterns we describe. ML can point at unusual activity no rule covers. Those ML-only
alerts are leads for review, labelled "Anomalous Activity".

**16. How do you know the ML and rules agree?**
The Analytics page shows how many events inside rule alerts the model also flagged. That is overlap
between two methods, not a measure of correctness.

## Scoring

**17. How is the threat score calculated?**
Seven components add whole-number points, capped at 100: threat type, attempts over the threshold,
frequency, affected accounts, ML score, source-IP behaviour, and escalation indicators. Bands: LOW
0-29, MEDIUM 30-59, HIGH 60-79, CRITICAL 80-100.

**18. Are the weights scientific?**
No. They are judgement-based and configurable. Their value is that they are transparent: each alert
shows exactly which factors gave which points.

## Evaluation

**19. How did you test it?**
Unit tests for every stage, an end-to-end test, bad-file and hostile-input tests, and a comparison
against the generator's answer key. The generator says how many attacks of each kind it injected, and
we check the rules found at least that many.

**20. Does that prove it works on real attacks?**
No. The data is simulated by the same author who wrote the rules. It shows the code does what it was
designed to do. Real logs would need tuning and proper evaluation. That is listed under future work.

## Security

**21. How do you protect against SQL injection?**
Every query uses `?` parameters. Sort columns come from fixed whitelists. Search wildcards are
escaped. A test sends hundreds of hostile query strings.

**22. And XSS, since logs are attacker-controlled?**
Log data is escaped before display, and a Content-Security-Policy blocks scripts from other
sources. A test stores `<script>` in a username and checks it is returned as plain text.

**23. What is CSV injection?**
Cells starting with `=`, `+`, `-` or `@` can run as formulas when opened in Excel. Exports prefix
them with a quote.

**24. How is file upload secured?**
Extension allow-list, 10 MB limit, sanitized names, random stored names, and rejected files are
deleted. Files are only read as text and never executed.

**25. What security is missing?**
No login and no CSRF protection, so it must stay on `127.0.0.1`. These are listed as limitations.

## Design

**26. Why SQLite and Flask?**
Both are simple and run on Windows with no setup, which suits a single-user academic tool.
SQLite would not suit many concurrent analysts.

**27. Why store `threat_events`?**
It links each alert to the exact log rows that caused it. That powers the related-events table and
the `alert_ids` column in the logs export.

**28. What happens if analysis fails halfway?**
Everything is saved in one transaction, so a failure leaves the previous results unchanged.

**29. How are Linux and Windows logs handled?**
Each has its own parser that maps fields to one standard record, and the same rules run on
all of them. Linux logs have no event IDs, so rules also match on event type.

## Honest improvement questions

**30. What would you do next?**
Add login and CSRF protection, run analysis in the background, train the model on a clean baseline,
evaluate on a public labelled dataset, correlate across sources, and add notifications.

**31. What was the hardest part?**
Be ready with your own answer. Good candidates: sliding-window detection that merges overlapping
bursts into one alert, keeping the score explanation consistent with the score, or making ML
results line up with log rows.

## Phrases to avoid

- "It is 95% accurate." (No figure exists.)
- "It detects all attacks." (It detects the patterns its rules describe.)
- "The AI knows what is an attack." (It flags unusual behaviour.)