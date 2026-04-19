/**
 * abac.js — Attribute-Based Access Control Engine
 *
 * ABAC makes access decisions based on ATTRIBUTES of:
 *   - the Subject (user)    e.g. department, clearance, location
 *   - the Resource          e.g. type, classification, owner
 *   - the Action            e.g. read, write, delete, approve
 *   - the Environment       e.g. time of day, IP address
 *
 * Policies are rules that combine these attributes with logical conditions.
 * The engine evaluates ALL matching policies and uses a "deny-overrides" strategy:
 * if ANY policy denies, access is denied even if another policy would allow it.
 */

// ─────────────────────────────────────────────
// 1. USER DATABASE  (Subjects + their attributes)
// ─────────────────────────────────────────────
const USERS = [
  {
    id: "u1",
    name: "Alice Okafor",
    department: "engineering",
    clearance: 3,          // 1=public, 2=internal, 3=confidential, 4=secret
    role: "engineer",
    location: "office",
    contractType: "fulltime",
    avatar: "AO",
  },
  {
    id: "u2",
    name: "Bob Mensah",
    department: "finance",
    clearance: 4,
    role: "manager",
    location: "office",
    contractType: "fulltime",
    avatar: "BM",
  },
  {
    id: "u3",
    name: "Carol Eze",
    department: "hr",
    clearance: 2,
    role: "analyst",
    location: "remote",
    contractType: "fulltime",
    avatar: "CE",
  },
  {
    id: "u4",
    name: "David Adeyemi",
    department: "engineering",
    clearance: 1,
    role: "intern",
    location: "office",
    contractType: "contractor",
    avatar: "DA",
  },
  {
    id: "u5",
    name: "Eve Nwosu",
    department: "finance",
    clearance: 3,
    role: "auditor",
    location: "remote",
    contractType: "contractor",
    avatar: "EN",
  },
];

// ─────────────────────────────────────────────
// 2. RESOURCE DATABASE
// ─────────────────────────────────────────────
const RESOURCES = [
  {
    id: "r1",
    name: "Source Code Repository",
    type: "code",
    classification: 2,       // minimum clearance needed to access
    ownerDept: "engineering",
    allowedActions: ["read", "write", "delete"],
  },
  {
    id: "r2",
    name: "Financial Reports Q4",
    type: "document",
    classification: 3,
    ownerDept: "finance",
    allowedActions: ["read", "write", "approve"],
  },
  {
    id: "r3",
    name: "Employee Salary Data",
    type: "database",
    classification: 4,
    ownerDept: "hr",
    allowedActions: ["read", "write"],
  },
  {
    id: "r4",
    name: "Public Company Blog",
    type: "content",
    classification: 1,
    ownerDept: "marketing",
    allowedActions: ["read", "write"],
  },
  {
    id: "r5",
    name: "Server Config Files",
    type: "config",
    classification: 3,
    ownerDept: "engineering",
    allowedActions: ["read", "write", "delete"],
  },
  {
    id: "r6",
    name: "Audit Logs",
    type: "log",
    classification: 3,
    ownerDept: "finance",
    allowedActions: ["read", "approve"],
  },
];

// ─────────────────────────────────────────────
// 3. POLICY ENGINE
//    Each policy has: name, description, effect ("allow"|"deny"),
//    and a condition function(subject, resource, action, environment)
// ─────────────────────────────────────────────
const POLICIES = [
  {
    id: "p1",
    name: "Clearance must meet resource classification",
    description: "A user's clearance level must be ≥ the resource's classification.",
    effect: "deny",
    condition: (s, r) => s.clearance < r.classification,
  },
  {
    id: "p2",
    name: "Contractors cannot delete resources",
    description: "Contract employees are not permitted to delete any resource.",
    effect: "deny",
    condition: (s, r, a) => s.contractType === "contractor" && a === "delete",
  },
  {
    id: "p3",
    name: "Remote users cannot write config files",
    description: "Users working remotely cannot modify server configuration files.",
    effect: "deny",
    condition: (s, r, a) => s.location === "remote" && r.type === "config" && a === "write",
  },
  {
    id: "p4",
    name: "Interns have read-only access",
    description: "Interns may only read resources; they cannot write, delete, or approve.",
    effect: "deny",
    condition: (s, r, a) => s.role === "intern" && a !== "read",
  },
  {
    id: "p5",
    name: "Finance resources require finance or audit role",
    description: "Only finance staff and auditors can access finance-owned resources.",
    effect: "deny",
    condition: (s, r) =>
      r.ownerDept === "finance" &&
      s.department !== "finance" &&
      s.role !== "auditor",
  },
  {
    id: "p6",
    name: "HR data accessible only to HR department",
    description: "Employee data can only be accessed by HR department staff.",
    effect: "deny",
    condition: (s, r) => r.type === "database" && r.ownerDept === "hr" && s.department !== "hr",
  },
  {
    id: "p7",
    name: "After-hours write restriction",
    description: "Write and delete operations are blocked outside 07:00–20:00.",
    effect: "deny",
    condition: (s, r, a, env) => {
      const h = env.hour;
      return (a === "write" || a === "delete") && (h < 7 || h >= 20);
    },
  },
  {
    id: "p8",
    name: "Action must be supported by resource",
    description: "The requested action must be in the resource's allowed action list.",
    effect: "deny",
    condition: (s, r, a) => !r.allowedActions.includes(a),
  },
  {
    id: "p9",
    name: "Approve action requires manager role",
    description: "Only managers can approve documents.",
    effect: "deny",
    condition: (s, r, a) => a === "approve" && s.role !== "manager" && s.role !== "auditor",
  },
  {
    id: "p10",
    name: "Default allow",
    description: "If no deny policy is triggered, access is granted.",
    effect: "allow",
    condition: () => true,
  },
];

// ─────────────────────────────────────────────
// 4. ACCESS DECISION FUNCTION
// ─────────────────────────────────────────────
/**
 * evaluate(userId, resourceId, action, environment)
 * Returns { decision: "allow"|"deny", reasons: [...], triggered: [...] }
 */
function evaluate(userId, resourceId, action, environment = {}) {
  const subject  = USERS.find(u => u.id === userId);
  const resource = RESOURCES.find(r => r.id === resourceId);
  const env = { hour: new Date().getHours(), ...environment };

  if (!subject || !resource) {
    return { decision: "deny", reasons: ["Unknown user or resource."], triggered: [] };
  }

  const triggered = [];
  let denied = false;

  for (const policy of POLICIES) {
    if (policy.condition(subject, resource, action, env)) {
      triggered.push(policy);
      if (policy.effect === "deny") {
        denied = true;
      }
    }
  }

  return {
    decision: denied ? "deny" : "allow",
    subject,
    resource,
    action,
    env,
    triggered,
    deniedBy: triggered.filter(p => p.effect === "deny"),
    allowedBy: triggered.filter(p => p.effect === "allow"),
  };
}

// ─────────────────────────────────────────────
// 5. TEST CASES
// ─────────────────────────────────────────────
const TEST_CASES = [
  {
    id: "tc1",
    description: "Alice (engineer, clearance 3) reads Source Code Repository",
    userId: "u1", resourceId: "r1", action: "read",
    expected: "allow",
  },
  {
    id: "tc2",
    description: "David (intern, clearance 1) tries to write to Source Code Repository",
    userId: "u4", resourceId: "r1", action: "write",
    expected: "deny",
  },
  {
    id: "tc3",
    description: "Bob (finance manager, clearance 4) approves Financial Reports",
    userId: "u2", resourceId: "r2", action: "approve",
    expected: "allow",
  },
  {
    id: "tc4",
    description: "Alice (engineering, clearance 3) tries to read Financial Reports",
    userId: "u1", resourceId: "r2", action: "read",
    expected: "deny",
  },
  {
    id: "tc5",
    description: "Carol (HR, clearance 2) reads Employee Salary Data",
    userId: "u3", resourceId: "r3", action: "read",
    expected: "deny",  // clearance 2 < classification 4
  },
  {
    id: "tc6",
    description: "Bob (finance, clearance 4) reads Employee Salary Data",
    userId: "u2", resourceId: "r3", action: "read",
    expected: "deny",  // not HR department
  },
  {
    id: "tc7",
    description: "Eve (contractor auditor, remote) reads Audit Logs",
    userId: "u5", resourceId: "r6", action: "read",
    expected: "allow",
  },
  {
    id: "tc8",
    description: "David (contractor intern) tries to delete Source Code",
    userId: "u4", resourceId: "r1", action: "delete",
    expected: "deny",  // intern + contractor both block this
  },
  {
    id: "tc9",
    description: "Carol (remote) tries to write Server Config Files",
    userId: "u3", resourceId: "r5", action: "write",
    expected: "deny",  // remote + insufficient clearance
  },
  {
    id: "tc10",
    description: "Alice (engineer) writes Server Config Files during business hours",
    userId: "u1", resourceId: "r5", action: "write",
    expected: "allow",
  },
  {
    id: "tc11",
    description: "Anyone reads Public Company Blog",
    userId: "u4", resourceId: "r4", action: "read",
    expected: "allow",
  },
  {
    id: "tc12",
    description: "After-hours write attempt (simulated at hour 23)",
    userId: "u1", resourceId: "r1", action: "write",
    environment: { hour: 23 },
    expected: "deny",
  },
];

function runAllTests() {
  return TEST_CASES.map(tc => {
    const result = evaluate(tc.userId, tc.resourceId, tc.action, tc.environment || {});
    return {
      ...tc,
      result,
      passed: result.decision === tc.expected,
    };
  });
}

// Export for browser use
window.ABAC = { USERS, RESOURCES, POLICIES, TEST_CASES, evaluate, runAllTests };
