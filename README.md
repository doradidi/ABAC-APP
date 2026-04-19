Attribute-Based Access Control (ABAC) System
A fully working ABAC implementation for a local application, featuring a policy engine, 5 users with rich attributes, 6 resources, 10 policies, and 12 automated test cases.

What is ABAC?
Unlike Role-Based Access Control (RBAC) which only checks what role you have, ABAC makes decisions based on multiple attributes simultaneously:

Attribute Category	Examples
Subject (user)	department, clearance level, role, location, contract type
Resource	type, classification level, owner department
Action	read, write, delete, approve
Environment	time of day, IP address
Project Structure
abac-app/
├── index.html     # Interactive dashboard (policy evaluator + test runner)
├── abac.js        # Core ABAC engine (users, resources, policies, evaluator)
├── style.css      # Dark terminal-style UI
└── README.md
How It Works
The Engine (abac.js)
The evaluate(userId, resourceId, action, environment) function:

Looks up the subject and resource by ID
Evaluates ALL 10 policies against the request
Applies deny-overrides strategy: if any policy returns deny, the final decision is deny
Returns the decision plus which policies triggered (and why)
Policies
Policy	Effect	Rule
p1	DENY	User clearance must be ≥ resource classification
p2	DENY	Contractors cannot delete resources
p3	DENY	Remote users cannot write config files
p4	DENY	Interns are read-only
p5	DENY	Finance resources require finance dept or auditor role
p6	DENY	HR database accessible only to HR dept
p7	DENY	Writes and deletes blocked outside 07:00–20:00
p8	DENY	Requested action must be in resource's allowed list
p9	DENY	Approve action requires manager or auditor role
p10	ALLOW	Default allow (if no deny triggered)
Users (Subjects)
Name	Dept	Clearance	Role	Location	Contract
Alice Okafor	Engineering	3 – Confidential	Engineer	Office	Full-time
Bob Mensah	Finance	4 – Secret	Manager	Office	Full-time
Carol Eze	HR	2 – Internal	Analyst	Remote	Full-time
David Adeyemi	Engineering	1 – Public	Intern	Office	Contractor
Eve Nwosu	Finance	3 – Confidential	Auditor	Remote	Contractor
Running
Open index.html in a browser — no server required.

Section 01: Select a user, resource, and action → click "Evaluate Access" to see which policies triggered
Section 02: Click "Run All Tests" to execute all 12 test cases
Section 03: Browse all active policies
Section 04: View the user attribute store
Submitting via GitHub
git init
git add .
git commit -m "Add ABAC system with policy engine and test cases"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/abac-app.git
git push -u origin main
